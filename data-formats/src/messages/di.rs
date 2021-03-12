use serde::{Serialize, Deserialize, Serializer};
use serde::ser::SerializeSeq;

use super::{Message, InternalMessage, ParseError};

#[derive(Debug, Deserialize)]
pub struct DIAppStart (
    String,
    #[serde(skip)]
    u8,  // This is a trick to make serde produce and expect a tuple....
);

impl Serialize for DIAppStart {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&self.0)?;
        seq.end()
    }
}

impl DIAppStart {
    pub fn new(mfg_info: &str) -> Self {
        DIAppStart(
            mfg_info.to_string(),
            0,
        )
    }

    pub fn get_mfg_info(&self) -> &str {
        &self.0
    }
}

impl Message for DIAppStart {
    fn message_type() -> u8 {
        10
    }

    fn from_wire(body: &[u8]) -> Result<Self, ParseError> {
        Ok(serde_cbor::from_slice(body)?)
    }
}

impl InternalMessage for DIAppStart {}

#[derive(Debug, Serialize, Deserialize)]
pub struct DISetCredentials (
    Vec<u8>,
    #[serde(skip)]
    u8,  // This is a trick to make serde produce and expect a tuple....
);

impl DISetCredentials {
    pub fn new(ov_header: Vec<u8>) -> Self {
        DISetCredentials (
            ov_header,
            0,
        )
    }

    pub fn get_ov_header(&self) -> &[u8] {
        &self.0
    }
}

impl Message for DISetCredentials {
    fn message_type() -> u8 {
        11
    }

    fn from_wire(body: &[u8]) -> Result<Self, ParseError> {
        Ok(serde_cbor::from_slice(body)?)
    }
}

impl InternalMessage for DISetCredentials {}
