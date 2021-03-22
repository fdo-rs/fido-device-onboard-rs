use std::convert::TryFrom;

use aws_nitro_enclaves_cose::COSESign1;
use openssl::{
    pkey::{PKey, PKeyRef, Private, Public},
    x509::X509,
};
use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::{
    constants::HashType,
    errors::Result,
    publickey::{PublicKey, X5Chain},
    types::{Guid, HMac, Hash, RendezvousInfo},
    Error,
};

#[derive(Debug, Serialize_tuple, Deserialize, Clone)]
pub struct OwnershipVoucher {
    // A lot of this is kept as u8 vectors, because they'll need to be cryptographically
    //  validated (digests or signature)
    header: Vec<u8>,
    header_hmac: HMac,
    device_certificate_chain: Option<Vec<u8>>,
    entries: Vec<Vec<u8>>,
}

impl OwnershipVoucher {
    pub fn new(
        header: Vec<u8>,
        header_hmac: HMac,
        device_certificate_chain: Option<Vec<u8>>,
    ) -> Self {
        OwnershipVoucher {
            header,
            header_hmac,
            device_certificate_chain,
            entries: Vec::new(),
        }
    }

    fn hdr_hash(&self) -> Vec<u8> {
        let mut hdr_hash = Vec::with_capacity(self.header.len() + self.header_hmac.value().len());
        hdr_hash.extend_from_slice(&self.header);
        hdr_hash.extend_from_slice(&self.header_hmac.value());
        hdr_hash
    }

    pub fn device_cert_signers(&self) -> Result<Vec<X509>> {
        if self.device_certificate_chain.is_none() {
            return Ok(Vec::new());
        }
        Ok(
            X5Chain::from_slice(&self.device_certificate_chain.as_ref().unwrap())?
                .into_chain()
                .drain(..)
                .skip(1)
                .collect(),
        )
    }

    pub fn device_certificate(&self) -> Result<Option<X509>> {
        if self.device_certificate_chain.is_none() {
            return Ok(None);
        }
        Ok(
            X5Chain::from_slice(&self.device_certificate_chain.as_ref().unwrap())?
                .into_chain()
                .drain(..)
                .next(),
        )
    }

    pub fn extend(
        &mut self,
        owner_private_key: &PKeyRef<Private>,
        hash_type: Option<HashType>,
        next_party: &PublicKey,
    ) -> Result<()> {
        // Check if the owner passed in the correct private key
        let (last_hash, owner_pubkey) = if self.entries.is_empty() {
            (
                Hash::new(hash_type, &self.hdr_hash())?,
                self.get_header()?.public_key,
            )
        } else {
            let lastrawentry = &self.entries[self.entries.len() - 1];
            let lastsignedentry = COSESign1::from_bytes(&lastrawentry)?;
            let lastentry: OwnershipVoucherEntry =
                serde_cbor::from_slice(&lastsignedentry.get_payload(None)?)?;
            // Check whether the hash_type passed is identical to the previous entry, or is not passed at all.
            let hash_type = if let Some(hash_type) = hash_type {
                if lastentry.hash_previous_entry.get_type() != hash_type {
                    return Err(Error::InconsistentValue("hash-type"));
                }
                hash_type
            } else {
                lastentry.hash_previous_entry.get_type()
            };
            (
                Hash::new(Some(hash_type), lastrawentry)?,
                lastentry.public_key,
            )
        };
        if !owner_pubkey.matches_pkey(&owner_private_key)? {
            return Err(Error::NonOwnerKey);
        }

        // Create new entry
        let hdrinfo_hash = Hash::new(hash_type, &self.get_header()?.get_info()?)?;
        let new_entry = OwnershipVoucherEntry {
            hash_previous_entry: last_hash,
            hash_header_info: hdrinfo_hash,
            public_key: next_party.clone(),
        };
        let new_entry = serde_cbor::to_vec(&new_entry)?;

        // Sign with private key
        let signed_new_entry = COSESign1::new(
            &new_entry,
            &aws_nitro_enclaves_cose::sign::HeaderMap::new(),
            owner_private_key,
        )?;

        // Append
        self.entries.push(signed_new_entry.as_bytes(true)?);

        Ok(())
    }

    pub fn get_header(&self) -> Result<OwnershipVoucherHeader> {
        serde_cbor::from_slice(&self.header).map_err(|e| e.into())
    }
}

impl<'a> OwnershipVoucher {
    pub fn iter_entries(&'a self) -> Result<EntryIter> {
        let hdr = self.get_header()?;
        let hdrinfo = hdr.get_info()?;

        Ok(EntryIter {
            voucher: self,
            pubkey: hdr.public_key.clone(),
            header: hdr,
            headerinfo: hdrinfo,
            index: 0,
            errored: false,
        })
    }
}

#[derive(Debug)]
pub struct EntryIter<'a> {
    voucher: &'a OwnershipVoucher,
    pubkey: PublicKey,
    header: OwnershipVoucherHeader,
    headerinfo: Vec<u8>,
    index: usize,
    errored: bool,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<OwnershipVoucherEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            return Some(Err(Error::PreviousEntryFailed));
        }
        if self.index >= self.voucher.entries.len() {
            return None;
        }

        let entry = self.process_element(&self.voucher.entries[self.index]);

        if !entry.is_ok() {
            self.errored = true;
        }

        self.index += 1;

        Some(entry)
    }
}

impl<'a> EntryIter<'a> {
    pub fn next_pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn process_element(&mut self, element: &'a [u8]) -> Result<OwnershipVoucherEntry> {
        let entry = aws_nitro_enclaves_cose::COSESign1::from_bytes(element)?;
        let key = self.pubkey.as_pkey()?;
        let payload = entry.get_payload(Some(&key))?;

        let entry: OwnershipVoucherEntry = serde_cbor::from_slice(&payload)?;

        // Compare the HashPreviousEntry to either (HeaderTag || HeaderHmac) or the previous entry
        let mut hdr_hash =
            Vec::with_capacity(self.voucher.header.len() + self.voucher.header_hmac.value().len());
        hdr_hash.extend_from_slice(&self.voucher.header);
        hdr_hash.extend_from_slice(&self.voucher.header_hmac.value());
        let other = if self.index == 0 {
            &hdr_hash
        } else {
            &self.voucher.entries[self.index - 1]
        };
        entry.hash_previous_entry.compare_data(other)?;

        // Compare the HeaderInfo hash
        entry.hash_header_info.compare_data(&self.headerinfo)?;

        // Set the next public key to the key in this entry
        self.pubkey = entry.public_key.clone();

        // Return
        Ok(entry)
    }
}

#[derive(Debug, Deserialize, Serialize_tuple)]
pub struct OwnershipVoucherHeader {
    pub protocol_version: u16,
    pub guid: Guid,
    pub rendezvous_info: RendezvousInfo,
    pub device_info: String,
    pub public_key: PublicKey,
    pub device_certificate_chain_hash: Option<Hash>,
}

impl OwnershipVoucherHeader {
    pub fn new(
        protocol_version: u16,
        guid: Guid,
        rendezvous_info: RendezvousInfo,
        device_info: String,
        public_key: PublicKey,
        device_certificate_chain_hash: Option<Hash>,
    ) -> Self {
        OwnershipVoucherHeader {
            protocol_version,
            guid,
            rendezvous_info,
            device_info,
            public_key,
            device_certificate_chain_hash,
        }
    }

    fn get_info(&self) -> Result<Vec<u8>> {
        let device_info_bytes = self.device_info.as_bytes();
        let mut hdrinfo = Vec::with_capacity(self.guid.len() + device_info_bytes.len());
        hdrinfo.extend_from_slice(&self.guid);
        hdrinfo.extend_from_slice(&device_info_bytes);

        Ok(hdrinfo)
    }
}

impl TryFrom<&OwnershipVoucherHeader> for Vec<u8> {
    type Error = Error;

    fn try_from(ovh: &OwnershipVoucherHeader) -> Result<Vec<u8>> {
        serde_cbor::to_vec(&ovh).map_err(|e| e.into())
    }
}

// TODO: From COSE_X509
type OwnershipVoucherDeviceCertificate = Vec<u8>;

#[derive(Debug, Deserialize, Serialize_tuple)]
pub struct OwnershipVoucherEntry {
    pub hash_previous_entry: Hash,
    pub hash_header_info: Hash,
    pub public_key: PublicKey,
}
