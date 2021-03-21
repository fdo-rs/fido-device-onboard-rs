use serde::{Serialize, Deserialize};
use serde_tuple::Serialize_tuple;

use super::{Message, ParseError};

use crate::{
    types::Nonce,
};

#[derive(Debug, Deserialize)]
pub struct Hello {}

impl Hello {
    pub fn new() -> Self {
        Hello {}
    }
}

impl Message for Hello {
    fn message_type() -> u8 {
        20
    }
}

impl Serialize for Hello {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let seq = serializer.serialize_seq(Some(0))?;
        seq.end()
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloAck {
    nonce3: Nonce,
}

impl HelloAck {
    pub fn new(nonce3: Nonce) -> Self {
        HelloAck {
            nonce3,
        }
    }

    pub fn nonce3(&self) -> &Nonce {
        &self.nonce3
    }
}

impl Message for HelloAck {
    fn message_type() -> u8 {
        21
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct OwnerSign {
    // TODO
    data: u8,
}

impl OwnerSign {

}

impl Message for OwnerSign {
    fn message_type() -> u8 {
        22
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AcceptOwner {
    wait_seconds: u32,
}

impl AcceptOwner {
    pub fn new(wait_seconds: u32) -> Self {
        AcceptOwner {
            wait_seconds,
        }
    }

    pub fn wait_seconds(&self) -> u32 {
        self.wait_seconds
    }
}
