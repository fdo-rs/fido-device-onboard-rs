use std::convert::TryFrom;

use openssl::pkey::{PKeyRef, Private};
use serde::{Deserialize, Serialize, Serializer, Deserializer};

use crate::{
    constants::HashType,
    errors::Result,
    publickey::PublicKey,
    types::{Guid, HMac, Hash, RendezvousInfo},
    Error,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnershipVoucher(
    // A lot of this is kept as u8 vectors, because they'll need to be cryptographically
    //  validated (digests or signature)
    Vec<u8>,              // OVHeaderTag
    Vec<u8>,              // OVHeaderHMac
    Option<Vec<Vec<u8>>>, // OVDevCertChain
    Vec<Vec<u8>>,         // OVEntries
);

impl OwnershipVoucher {
    pub(crate) fn new() -> Self {

        todo!();
    }

    fn hdr_hash(&self) -> Vec<u8> {
        let mut hdr_hash = Vec::with_capacity(self.0.len() + self.1.len());
        hdr_hash.extend_from_slice(&self.0);
        hdr_hash.extend_from_slice(&self.1);
        hdr_hash
    }

    pub fn extend(
        &mut self,
        owner_private_key: &PKeyRef<Private>,
        hash_type: Option<HashType>,
        next_party: &PublicKey,
    ) -> Result<()> {
        // Check if the owner passed in the correct private key
        let (last_hash, owner_pubkey) = if self.3.is_empty() {
            (
                Hash::new(hash_type, &self.hdr_hash())?,
                self.get_raw_header()?.4,
            )
        } else {
            let lastrawentry = &self.3[self.3.len() - 1];
            let lastentry: RawOwnershipVoucherEntry = serde_cbor::from_slice(&lastrawentry)?;
            // Check whether the hash_type passed is identical to the previous entry, or is not passed at all.
            let hash_type = if let Some(hash_type) = hash_type {
                if lastentry.0.get_type() != hash_type {
                    return Err(Error::InconsistentValue);
                }
                hash_type
            } else {
                lastentry.0.get_type()
            };
            (Hash::new(Some(hash_type), lastrawentry)?, lastentry.2)
        };
        if !owner_private_key.public_eq(&owner_pubkey.as_pkey()?.as_ref()) {
            return Err(Error::NonOwnerKey);
        }

        // Create new entry
        let hdrinfo_hash = Hash::new(hash_type, &self.get_raw_header()?.get_info()?)?;
        let new_entry = OwnershipVoucherEntry {
            hash_previous_entry: last_hash,
            hash_header_info: hdrinfo_hash,
            public_key: next_party.clone(),
        };
        let new_entry = RawOwnershipVoucherEntry::from(new_entry);
        let new_entry = serde_cbor::to_vec(&new_entry)?;

        // Sign with private key
        let signed_new_entry = aws_nitro_enclaves_cose::COSESign1::new(
            &new_entry,
            &aws_nitro_enclaves_cose::sign::HeaderMap::new(),
            owner_private_key,
        )?;

        // Append
        self.3.push(signed_new_entry.as_bytes(true)?);

        Ok(())
    }

    pub fn get_header(&self) -> Result<OwnershipVoucherHeader> {
        self.get_raw_header().map(|e| e.into())
    }

    fn get_raw_header(&self) -> Result<RawOwnershipVoucherHeader> {
        serde_cbor::from_slice(&self.0).map_err(|e| e.into())
    }
}

impl<'a> OwnershipVoucher {
    pub fn iter_entries(&'a self) -> Result<EntryIter> {
        let hdr = self.get_raw_header()?;
        let hdrinfo = hdr.get_info()?;

        Ok(EntryIter {
            voucher: self,
            pubkey: hdr.4.clone(),
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
    header: RawOwnershipVoucherHeader,
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
        if self.index > self.voucher.3.len() {
            return None;
        }

        let entry = self.process_element(&self.voucher.3[self.index]);

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

        let entry: RawOwnershipVoucherEntry = serde_cbor::from_slice(&payload)?;
        let entry = OwnershipVoucherEntry::from(entry);

        // Compare the HashPreviousEntry to either (HeaderTag || HeaderHmac) or the previous entry
        let mut hdr_hash = Vec::with_capacity(self.voucher.0.len() + self.voucher.1.len());
        hdr_hash.extend_from_slice(&self.voucher.0);
        hdr_hash.extend_from_slice(&self.voucher.1);
        let other = if self.index == 0 {
            &hdr_hash
        } else {
            &self.voucher.3[self.index - 1]
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

#[derive(Debug, Serialize, Deserialize)]
struct RawOwnershipVoucherHeader(
    u16,            // OVProtVer
    Guid,           // OVGuid
    RendezvousInfo, // OVRVInfo
    String,         // OVDeviceInfo
    PublicKey,      // OVPubKey
    Option<Hash>,   // OVDevCertChainHash
);

impl RawOwnershipVoucherHeader {
    fn get_info(&self) -> Result<Vec<u8>> {
        let device_info_bytes = self.3.as_bytes();
        let mut hdrinfo = Vec::with_capacity(self.1.len() + device_info_bytes.len());
        hdrinfo.extend_from_slice(&self.1);
        hdrinfo.extend_from_slice(&device_info_bytes);

        Ok(hdrinfo)
    }
}

#[derive(Debug)]
pub struct OwnershipVoucherHeader {
    pub protocol_version: u16,
    pub guid: Guid,
    pub rendezvous_info: RendezvousInfo,
    pub device_info: String,
    pub public_key: PublicKey,
    pub device_certificate_chain_hash: Option<Hash>,
}

impl From<OwnershipVoucherHeader> for RawOwnershipVoucherHeader {
    fn from(hdr: OwnershipVoucherHeader) -> RawOwnershipVoucherHeader {
        RawOwnershipVoucherHeader(
            hdr.protocol_version,
            hdr.guid,
            hdr.rendezvous_info,
            hdr.device_info,
            hdr.public_key,
            hdr.device_certificate_chain_hash,
        )
    }
}

impl From<RawOwnershipVoucherHeader> for OwnershipVoucherHeader {
    fn from(raw: RawOwnershipVoucherHeader) -> OwnershipVoucherHeader {
        OwnershipVoucherHeader {
            protocol_version: raw.0,
            guid: raw.1,
            rendezvous_info: raw.2,
            device_info: raw.3,
            public_key: raw.4,
            device_certificate_chain_hash: raw.5,
        }
    }
}

impl TryFrom<OwnershipVoucherHeader> for Vec<u8> {
    type Error = Error;

    fn try_from(ovh: OwnershipVoucherHeader) -> Result<Vec<u8>> {
        serde_cbor::to_vec(&RawOwnershipVoucherHeader::from(ovh))
        .map_err(|e| e.into())
    }
}

// TODO: From COSE_X509
type OwnershipVoucherDeviceCertificate = Vec<u8>;

#[derive(Debug)]
pub struct OwnershipVoucherEntry {
    hash_previous_entry: Hash,
    hash_header_info: Hash,
    public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawOwnershipVoucherEntry(Hash, Hash, PublicKey);

impl From<RawOwnershipVoucherEntry> for OwnershipVoucherEntry {
    fn from(raw: RawOwnershipVoucherEntry) -> Self {
        OwnershipVoucherEntry {
            hash_previous_entry: raw.0,
            hash_header_info: raw.1,
            public_key: raw.2,
        }
    }
}

impl From<OwnershipVoucherEntry> for RawOwnershipVoucherEntry {
    fn from(entry: OwnershipVoucherEntry) -> Self {
        RawOwnershipVoucherEntry(
            entry.hash_previous_entry,
            entry.hash_header_info,
            entry.public_key,
        )
    }
}
