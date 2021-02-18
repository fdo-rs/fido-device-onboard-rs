use std::convert::{TryFrom, TryInto};

use openssl::{
    ec::EcKeyRef,
    pkey::Public,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::Result,
    publickey::{PublicKey, PublicKeyBody},
    types::{Guid, HMac, Hash, RendezvousInfo},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnershipVoucher(
    Vec<u8>,                         // OVHeaderTag
    HMac,                                           // OVHeaderHMac
    Option<Vec<Vec<u8>>>, // OVDevCertChain
    Vec<Vec<u8>>,        // OVEntries
);

impl<'a> OwnershipVoucher {
    fn iter_entries(&'a self, pubkey: Option<&PublicKey>) -> EntryIter {
        EntryIter {
            voucher: self,
            pubkey: match pubkey {
                None => None,
                Some(key) => Some(key.clone()),
            },
            entry: 0,
        }
    }
}

#[derive(Debug)]
pub struct EntryIter<'a> {
    voucher: &'a OwnershipVoucher,
    pubkey: Option<PublicKey>,
    entry: usize,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<OwnershipVoucherEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.entry > self.voucher.3.len() {
            return None;
        }

        self.entry += 1;

        return Some(self.process_element(&self.voucher.3[self.entry-1]));
    }
}

impl<'a> EntryIter<'a> {
    fn process_element(&mut self, element: &'a [u8]) -> Result<OwnershipVoucherEntry> {
        let entry = aws_nitro_enclaves_cose::COSESign1::from_bytes(element)?;
        let (protected, payload) = match &self.pubkey {
            Some(key) => {
                let key = key.as_pkey()?;
                entry.get_protected_and_payload(Some(&key))
            }
            None => entry.get_protected_and_payload(None),
        }?;

        let entry: RawOwnershipVoucherEntry = serde_cbor::from_slice(&payload)?;
        let entry = OwnershipVoucherEntry::from(entry);

        self.pubkey = Some(entry.PubKey.clone());

        Ok(entry)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct OwnershipVoucherHeader(
    u16,            // OVProtVer
    Guid,           // OVGuid
    RendezvousInfo, // OVRVInfo
    String,         // OVDeviceInfo
    PublicKey,      // OVPubKey
    Option<Hash>,   // OVDevCertChainHash
);

// TODO: From COSE_X509
type OwnershipVoucherDeviceCertificate = Vec<u8>;

#[derive(Debug)]
pub struct OwnershipVoucherEntry {
    HashPreviousEntry: Hash,
    HashHeaderInfo: Hash,
    PubKey: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawOwnershipVoucherEntry(
    Hash,
    Hash,
    PublicKey,
);

impl From<RawOwnershipVoucherEntry> for OwnershipVoucherEntry {
    fn from(raw: RawOwnershipVoucherEntry) -> Self {
        OwnershipVoucherEntry {
            HashPreviousEntry: raw.0,
            HashHeaderInfo: raw.1,
            PubKey: raw.2,
        }
    }
}

impl From<OwnershipVoucherEntry> for RawOwnershipVoucherEntry {
    fn from(entry: OwnershipVoucherEntry) -> Self {
        RawOwnershipVoucherEntry(
            entry.HashPreviousEntry,
            entry.HashHeaderInfo,
            entry.PubKey,
        )
    }
}
