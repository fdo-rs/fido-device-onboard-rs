use thiserror::Error;

use aws_nitro_enclaves_cose::error::COSEError;
use fdo_data_formats::messages::{ClientMessage, ErrorMessage, Message, ServerMessage};

use crate::EncryptionKeys;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptographic error encrypting/decrypting")]
    Crypto(COSEError),
    #[error("Serialization/deserialization error")]
    Serde(#[from] serde_cbor::Error),
    #[error("Error parsing or generating request")]
    Parse(#[from] fdo_data_formats::messages::ParseError),
    #[error("Error performing request")]
    Request(#[from] reqwest::Error),
    #[error("Missing message type in response")]
    MissingMessageType,
    #[error("Invalid message type {0} encountered")]
    InvalidMessageType(String),
    #[error("Invalid message type {0} encountered, expected {1}")]
    InvalidMessage(u8, u8),
    #[error("Error returned by server: {0:?}")]
    Error(ErrorMessage),
}

impl From<COSEError> for Error {
    fn from(e: COSEError) -> Self {
        Error::Crypto(e)
    }
}

pub type RequestResult<MT> = Result<MT, Error>;

#[derive(Debug)]
pub struct ServiceClient {
    base_url: String,
    client: reqwest::Client,
    authorization_token: Option<String>,
    encryption_keys: EncryptionKeys,
}

impl ServiceClient {
    pub fn new(base_url: &str) -> Self {
        ServiceClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            authorization_token: None,
            encryption_keys: EncryptionKeys::unencrypted(),
        }
    }

    pub async fn send_request<OM, SM>(
        &mut self,
        to_send: OM,
        new_keys: Option<EncryptionKeys>,
    ) -> RequestResult<SM>
    where
        OM: Message + ClientMessage,
        SM: Message + ServerMessage,
    {
        let to_send = to_send.to_wire()?;
        let to_send = self.encryption_keys.encrypt(&to_send)?;

        let url = format!("{}/fdo/100/msg/{}", &self.base_url, OM::message_type());

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(to_send);

        if let Some(authorization_token) = &self.authorization_token {
            req = req.header("Authorization", authorization_token);
        }

        if let Some(new_keys) = new_keys {
            self.encryption_keys = new_keys;
        }

        let resp = req.send().await?;

        let msgtype = resp
            .headers()
            .get("message-type")
            .ok_or(Error::MissingMessageType)?
            .to_str()
            .map_err(|_| Error::MissingMessageType)?;
        let msgtype = msgtype
            .parse::<u8>()
            .map_err(|_| Error::InvalidMessageType(msgtype.to_string()))?;

        if let Some(val) = resp.headers().get("authorization") {
            self.authorization_token = Some(val.to_str().unwrap().to_string());
        }

        let is_success = if resp.status().is_success() {
            if msgtype != SM::message_type() {
                return Err(Error::InvalidMessage(msgtype, SM::message_type()));
            }
            true
        } else {
            if msgtype != ErrorMessage::message_type() {
                return Err(Error::InvalidMessage(msgtype, ErrorMessage::message_type()));
            }
            false
        };

        let resp = resp.bytes().await?;

        if is_success {
            let resp = self.encryption_keys.decrypt(&resp)?;
            Ok(serde_cbor::from_slice(&resp)?)
        } else {
            Err(Error::Error(serde_cbor::from_slice(&resp)?))
        }
    }
}
