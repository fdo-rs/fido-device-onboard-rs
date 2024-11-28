//! COSE HeaderMap

use serde::{Deserialize, Serialize};
use serde_cbor::Error as CborError;
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
/// Implementation of header_map, with CborValue keys and CborValue values.
pub struct HeaderMap(
    #[serde(deserialize_with = "::serde_with::rust::maps_duplicate_key_is_error::deserialize")]
    BTreeMap<CborValue, CborValue>,
);

impl HeaderMap {
    /// Creates an empty HeaderMap
    pub fn new() -> Self {
        HeaderMap(BTreeMap::new())
    }

    /// Inserts an element into HeaderMap. Both key and value are CborValue.
    /// If key already has a value, that value is returned.
    pub fn insert(&mut self, key: CborValue, value: CborValue) -> Option<CborValue> {
        self.0.insert(key, value)
    }

    /// Returns the element at key.
    pub fn get(&self, key: &CborValue) -> Option<&CborValue> {
        self.0.get(key)
    }

    /// Returns true if HeaderMap has no elements, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parses a slice of bytes into a HeaderMap, if possible.
    pub fn from_bytes(header_map: &[u8]) -> Result<Self, CborError> {
        serde_cbor::from_slice(header_map)
    }
}

pub(crate) fn map_to_empty_or_serialized(map: &HeaderMap) -> Result<Vec<u8>, CborError> {
    if map.is_empty() {
        Ok(vec![])
    } else {
        Ok(serde_cbor::to_vec(map)?)
    }
}
