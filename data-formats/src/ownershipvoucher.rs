use std::ops::Range;

use openssl::pkey::{PKeyRef, Private};
use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::{
    cborparser::{ParsedArray, ParsedArraySize4, ParsedArraySize6, ParsedArraySizeDynamic},
    constants::HashType,
    errors::Result,
    publickey::{PublicKey, X5Chain},
    types::{COSESign, Guid, HMac, Hash, RendezvousInfo, UnverifiedValue},
    Error, Serializable,
};

const VOUCHER_PEM_TAG: &str = "OWNERSHIP VOUCHER";
const ACCEPTABLE_ASCII_RANGE: Range<u8> = 32..127;

#[derive(Debug)]
enum OwnershipVoucherIndex {
    Header = 0,
    HeaderHmac = 1,
    DeviceCertificateChain = 2,
    Entries = 3,
}

#[derive(Debug, Clone)]
pub struct OwnershipVoucher {
    contents: ParsedArray<ParsedArraySize4>,

    // Cached data
    cached_header: OwnershipVoucherHeader,
    cached_header_hmac: HMac,
    cached_device_certificate_chain: Option<X5Chain>,
    cached_entries: ParsedArray<ParsedArraySizeDynamic>,
}

impl Serializable for OwnershipVoucher {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader)?;

        let cached_header = contents.get(OwnershipVoucherIndex::Header as usize)?;
        let cached_header_hmac = contents.get(OwnershipVoucherIndex::HeaderHmac as usize)?;
        let cached_device_certificate_chain =
            contents.get(OwnershipVoucherIndex::DeviceCertificateChain as usize)?;
        let cached_entries = contents.get(OwnershipVoucherIndex::Entries as usize)?;

        Ok(OwnershipVoucher {
            contents,

            cached_header,
            cached_header_hmac,
            cached_device_certificate_chain,
            cached_entries,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        self.contents.serialize_to_writer(writer)
    }
}

impl OwnershipVoucher {
    pub fn from_parts(
        header: OwnershipVoucherHeader,
        header_hmac: HMac,
        entries: ParsedArray<ParsedArraySizeDynamic>,
    ) -> Result<Self> {
        let mut contents = unsafe { ParsedArray::new() };
        contents.set(OwnershipVoucherIndex::Header as usize, &header)?;
        contents.set(OwnershipVoucherIndex::HeaderHmac as usize, &header_hmac)?;
        contents.set::<Option<X5Chain>>(
            OwnershipVoucherIndex::DeviceCertificateChain as usize,
            &None,
        )?;
        contents.set(OwnershipVoucherIndex::Entries as usize, &entries)?;

        Ok(OwnershipVoucher {
            contents,

            cached_header: header,
            cached_header_hmac: header_hmac,
            cached_device_certificate_chain: None,
            cached_entries: entries,
        })
    }

    pub fn new(
        header: OwnershipVoucherHeader,
        header_hmac: HMac,
        device_certificate_chain: Option<X5Chain>,
    ) -> Result<Self> {
        let entries = ParsedArray::new_empty();

        let mut contents: ParsedArray<ParsedArraySize4> = unsafe { ParsedArray::new() };
        contents.set(OwnershipVoucherIndex::Header as usize, &header.contents)?;
        contents.set(OwnershipVoucherIndex::HeaderHmac as usize, &header_hmac)?;
        contents.set(
            OwnershipVoucherIndex::DeviceCertificateChain as usize,
            &device_certificate_chain,
        )?;
        contents.set(OwnershipVoucherIndex::Entries as usize, &entries)?;

        Ok(OwnershipVoucher {
            contents,

            cached_header: header,
            cached_header_hmac: header_hmac,
            cached_device_certificate_chain: device_certificate_chain,
            cached_entries: entries,
        })
    }

    pub fn from_pem(data: &[u8]) -> Result<Self> {
        let parsed = pem::parse(data)?;
        if parsed.tag != VOUCHER_PEM_TAG {
            return Err(Error::InvalidPemTag(parsed.tag));
        }
        Self::deserialize_data(&parsed.contents)
    }

    pub fn from_pem_or_raw(data: &[u8]) -> Result<Self> {
        if data[0] == data[1] && data[0] == b'-' {
            Self::from_pem(data)
        } else {
            Self::deserialize_data(data)
        }
    }

    pub fn to_pem(&self) -> Result<String> {
        let block = pem::Pem {
            tag: VOUCHER_PEM_TAG.to_string(),
            contents: self.serialize_data()?,
        };
        Ok(pem::encode(&block))
    }

    fn hash_type(&self) -> HashType {
        self.cached_header_hmac.get_type().inner_hash()
    }

    pub fn header_hmac(&self) -> &HMac {
        &self.cached_header_hmac
    }

    pub fn device_certificate_chain(&self) -> Option<&X5Chain> {
        self.cached_device_certificate_chain.as_ref()
    }

    pub fn device_certificate_chain_hash(&self, hash_type: HashType) -> Option<Result<Hash>> {
        if self.cached_device_certificate_chain.is_none() {
            None
        } else {
            Some(self.contents.get_hash(
                OwnershipVoucherIndex::DeviceCertificateChain as usize,
                hash_type,
            ))
        }
    }

    pub fn num_entries(&self) -> u16 {
        self.cached_entries.len() as u16
    }

    pub fn entry(&self, entry_num: usize) -> Result<OwnershipVoucherEntry> {
        self.cached_entries.get(entry_num)
    }

    pub fn extend(
        &mut self,
        owner_private_key: &PKeyRef<Private>,
        next_party: &PublicKey,
    ) -> Result<()> {
        let hdrinfo_hash = self.header().get_hdr_info_hash(self.hash_type())?;
        let (last_hash, current_owner_pubkey) = if self.cached_entries.is_empty() {
            (
                self.contents.get_hash_two_items(
                    OwnershipVoucherIndex::Header as usize,
                    OwnershipVoucherIndex::HeaderHmac as usize,
                    self.hash_type(),
                )?,
                self.header().manufacturer_public_key().clone(),
            )
        } else {
            let last_idx = self.cached_entries.len() - 1;

            let last_hash = self.cached_entries.get_hash(last_idx, self.hash_type())?;
            let lastentry: OwnershipVoucherEntry = self.cached_entries.get(last_idx)?;
            let lastentry: UnverifiedValue<OwnershipVoucherEntryPayload> =
                lastentry.get_payload_unverified()?;

            (
                last_hash,
                lastentry.get_unverified_value().public_key.clone(),
            )
        };

        if !current_owner_pubkey.matches_pkey(owner_private_key)? {
            return Err(Error::NonOwnerKey);
        }

        // Create new entry
        let new_entry = OwnershipVoucherEntryPayload {
            hash_previous_entry: last_hash,
            hash_header_info: hdrinfo_hash,
            public_key: next_party.clone(),
        };

        // Sign with private key
        let signed_new_entry = COSESign::new(&new_entry, None, owner_private_key)?;
        let signed_new_entry = OwnershipVoucherEntry::new(signed_new_entry);

        // Append
        self.cached_entries.push(&signed_new_entry)?;

        self.contents.set(3, &self.cached_entries)?;

        Ok(())
    }

    pub fn header(&self) -> &OwnershipVoucherHeader {
        &self.cached_header
    }
}

impl<'a> OwnershipVoucher {
    pub fn iter_entries(&'a self) -> Result<EntryIter> {
        Ok(EntryIter {
            voucher: self,
            index: 0,
            errored: false,

            last_pubkey: self.header().manufacturer_public_key().clone(),
        })
    }
}

#[derive(Debug)]
pub struct EntryIter<'a> {
    voucher: &'a OwnershipVoucher,
    index: usize,
    errored: bool,

    last_pubkey: PublicKey,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<OwnershipVoucherEntryPayload>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            log::warn!("Previous entry validation failed");
            return None;
        }
        if self.index >= self.voucher.cached_entries.len() {
            return None;
        }

        let entry = self.voucher.cached_entries.get(self.index);
        if let Err(e) = entry {
            log::warn!("Error getting next entry: {:?}", e);
            self.errored = true;
            return Some(Err(e));
        }
        let entry = self.process_element(entry.unwrap());

        if entry.is_err() {
            log::warn!("Error validating ownership voucher: {:?}", entry);
            self.errored = true;
        }

        self.index += 1;

        Some(entry)
    }
}

impl<'a> EntryIter<'a> {
    fn process_element(
        &mut self,
        entry: OwnershipVoucherEntry,
    ) -> Result<OwnershipVoucherEntryPayload> {
        let entry = entry.0;
        let entry: OwnershipVoucherEntryPayload = entry.get_payload(self.last_pubkey.pkey())?;

        // Compare the HashPreviousEntry to either (HeaderTag || HeaderHmac) or the previous entry
        let hash_previous_entry = if self.index == 0 {
            self.voucher.contents.get_hash_two_items(
                OwnershipVoucherIndex::Header as usize,
                OwnershipVoucherIndex::HeaderHmac as usize,
                entry.hash_previous_entry.get_type(),
            )?
        } else {
            self.voucher
                .cached_entries
                .get_hash(self.index - 1, entry.hash_previous_entry.get_type())?
        };
        match entry.hash_previous_entry.compare(&hash_previous_entry) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Error verifying hash of previous entry");
                return Err(e);
            }
        }

        // Compare the HeaderInfo hash
        let hdr_info_hash = self
            .voucher
            .header()
            .get_hdr_info_hash(entry.hash_header_info.get_type())?;
        match entry.hash_header_info.compare(&hdr_info_hash) {
            Ok(_) => {}
            Err(e) => {
                println!("Header hash: {:?}", hdr_info_hash);
                println!("Entry hash:  {:?}", entry.hash_header_info);
                log::error!("Error verifying header hash");
                return Err(e);
            }
        }

        // Set the next public key to the key in this entry
        self.last_pubkey = entry.public_key.clone();

        // Return
        Ok(entry)
    }
}

#[derive(Debug)]
#[repr(u8)]
enum OwnershipVoucherHeaderIndex {
    ProtocolVersion = 0,
    Guid = 1,
    RendezvousInfo = 2,
    DeviceInfo = 3,
    ManufacturerPublicKey = 4,
    DeviceCertificateChainHash = 5,
}

#[derive(Clone, Debug)]
pub struct OwnershipVoucherHeader {
    contents: ParsedArray<ParsedArraySize6>,

    cached_protocol_version: u16,
    cached_guid: Guid,
    cached_rendezvous_info: RendezvousInfo,
    cached_device_info: String,
    cached_manufacturer_public_key: PublicKey,
    cached_device_certificate_chain_hash: Option<Hash>,
}

impl OwnershipVoucherHeader {
    pub fn new(
        protocol_version: u16,
        guid: Guid,
        rendezvous_info: RendezvousInfo,
        device_info: String,
        manufacturer_public_key: PublicKey,
        device_certificate_chain_hash: Option<Hash>,
    ) -> Result<Self> {
        let device_info = device_info.trim().to_string();
        let mut contents = unsafe { ParsedArray::new() };
        contents.set(
            OwnershipVoucherHeaderIndex::ProtocolVersion as usize,
            &protocol_version,
        )?;
        contents.set(OwnershipVoucherHeaderIndex::Guid as usize, &guid)?;
        contents.set(
            OwnershipVoucherHeaderIndex::RendezvousInfo as usize,
            &rendezvous_info,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::DeviceInfo as usize,
            &device_info,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize,
            &manufacturer_public_key,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::DeviceCertificateChainHash as usize,
            &device_certificate_chain_hash,
        )?;

        Ok(OwnershipVoucherHeader {
            contents,

            cached_protocol_version: protocol_version,
            cached_guid: guid,
            cached_rendezvous_info: rendezvous_info,
            cached_device_info: device_info,
            cached_manufacturer_public_key: manufacturer_public_key,
            cached_device_certificate_chain_hash: device_certificate_chain_hash,
        })
    }

    pub fn protocol_version(&self) -> u16 {
        self.cached_protocol_version
    }

    pub fn guid(&self) -> &Guid {
        &self.cached_guid
    }

    pub fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.cached_rendezvous_info
    }

    pub fn device_info(&self) -> &str {
        &self.cached_device_info
    }

    pub fn manufacturer_public_key(&self) -> &PublicKey {
        &self.cached_manufacturer_public_key
    }

    pub fn manufacturer_public_key_hash(&self, hash_type: HashType) -> Result<Hash> {
        self.contents.get_hash(
            OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize,
            hash_type,
        )
    }

    pub fn device_certificate_chain_hash(&self) -> Option<&Hash> {
        self.cached_device_certificate_chain_hash.as_ref()
    }

    fn get_hdr_info_hash(&self, hash_type: HashType) -> Result<Hash> {
        // TODO: Check with FIDO Alliance whether this is correct.
        // For the HashPrevEntry, we compute with the actual CBOR type prefix,
        // while for hdr_info, the Intel implementation seemed to not do that.
        let guid: Guid = self
            .contents
            .get(OwnershipVoucherHeaderIndex::Guid as usize)?;
        let device_info: String = self
            .contents
            .get(OwnershipVoucherHeaderIndex::DeviceInfo as usize)?;
        let device_info = device_info.as_bytes();

        let mut data = Vec::with_capacity(guid.len() + device_info.len());
        data.extend_from_slice(&guid);
        data.extend_from_slice(device_info);

        Hash::from_data(hash_type, &data)
    }
}

fn check_device_info(device_info: &str) -> Result<()> {
    let mut chars = device_info.chars();
    let are_all_chars_supported_ascii = chars.all(|f| ACCEPTABLE_ASCII_RANGE.contains(&(f as u8)));
    if are_all_chars_supported_ascii {
        Ok(())
    } else {
        Err(Error::InconsistentValue("Invalid values in Device Info"))
    }
}

#[test]
fn test_check_device_info_unsupported_characters() {
    let device_info: String = "FDO\n".to_string();
    let is_device_info_valid = check_device_info(&device_info);
    assert!(is_device_info_valid.is_err());
}

#[test]
fn test_check_device_info_supported_characters() {
    let device_info: String = "FDO".to_string();
    let is_device_info_valid = check_device_info(&device_info);
    assert_eq!((), is_device_info_valid.unwrap());
}

impl Serializable for OwnershipVoucherHeader {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader)?;

        let cached_protocol_version =
            contents.get(OwnershipVoucherHeaderIndex::ProtocolVersion as usize)?;
        let cached_guid = contents.get(OwnershipVoucherHeaderIndex::Guid as usize)?;
        let cached_rendezvous_info =
            contents.get(OwnershipVoucherHeaderIndex::RendezvousInfo as usize)?;
        let cached_device_info: String =
            contents.get(OwnershipVoucherHeaderIndex::DeviceInfo as usize)?;
        check_device_info(&cached_device_info)?;
        let cached_manufacturer_public_key =
            contents.get(OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize)?;
        let cached_device_certificate_chain_hash =
            contents.get(OwnershipVoucherHeaderIndex::DeviceCertificateChainHash as usize)?;

        Ok(OwnershipVoucherHeader {
            contents,

            cached_protocol_version,
            cached_guid,
            cached_rendezvous_info,
            cached_device_info,
            cached_manufacturer_public_key,
            cached_device_certificate_chain_hash,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        check_device_info(&self.cached_device_info)?;
        self.contents.serialize_to_writer(writer)
    }
}

#[derive(Debug, Clone)]
pub struct OwnershipVoucherEntry(COSESign);

impl Serializable for OwnershipVoucherEntry {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        COSESign::deserialize_from_reader(reader).map(OwnershipVoucherEntry)
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        self.0.serialize_to_writer(writer)
    }
}

impl OwnershipVoucherEntry {
    pub fn new(sign: COSESign) -> Self {
        OwnershipVoucherEntry(sign)
    }
}

impl std::ops::Deref for OwnershipVoucherEntry {
    type Target = COSESign;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, Serialize_tuple, Clone)]
pub struct OwnershipVoucherEntryPayload {
    hash_previous_entry: Hash,
    hash_header_info: Hash,
    public_key: PublicKey,
}

impl OwnershipVoucherEntryPayload {
    pub fn new(
        hash_previous_entry: Hash,
        hash_header_info: Hash,
        public_key: PublicKey,
    ) -> Result<Self> {
        Ok(OwnershipVoucherEntryPayload {
            hash_previous_entry,
            hash_header_info,
            public_key,
        })
    }

    pub fn hash_previous_entry(&self) -> &Hash {
        &self.hash_previous_entry
    }

    pub fn hash_header_info(&self) -> &Hash {
        &self.hash_header_info
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}
