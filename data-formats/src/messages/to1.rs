use aws_nitro_enclaves_cose::COSESign1;
use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;

use super::{Message, ParseError};

use crate::types::{Guid, Nonce, SigInfo, TO0Data, TO1DataPayload};

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRV {
    guid: Guid,
    a_signature_info: SigInfo,
}

impl HelloRV {
    pub fn new(guid: Guid, a_signature_info: SigInfo) -> Self {
        HelloRV {
            guid,
            a_signature_info,
        }
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn a_signature_info(&self) -> &SigInfo {
        &self.a_signature_info
    }
}

impl Message for HelloRV {
    fn message_type() -> u8 {
        30
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRVAck {
    nonce4: Nonce,
    b_signature_info: SigInfo,
}

impl HelloRVAck {
    pub fn new(nonce4: Nonce, b_signature_info: SigInfo) -> Self {
        HelloRVAck {
            nonce4,
            b_signature_info,
        }
    }

    pub fn nonce4(&self) -> &Nonce {
        &self.nonce4
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.b_signature_info
    }
}

impl Message for HelloRVAck {
    fn message_type() -> u8 {
        31
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveToRV(COSESign1);

impl ProveToRV {
    pub fn new(token: COSESign1) -> Self {
        ProveToRV(token)
    }

    pub fn token(&self) -> &COSESign1 {
        &self.0
    }
}

impl Message for ProveToRV {
    fn message_type() -> u8 {
        32
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RVRedirect(COSESign1);

impl RVRedirect {
    pub fn new(to1d: COSESign1) -> Self {
        RVRedirect(to1d)
    }

    pub fn to1d(&self) -> &COSESign1 {
        &self.0
    }

    pub fn into_to1d(self) -> COSESign1 {
        self.0
    }
}

impl Message for RVRedirect {
    fn message_type() -> u8 {
        33
    }
}
