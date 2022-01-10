use std::{convert::TryFrom, str::FromStr};

use thiserror::Error;

use aws_nitro_enclaves_cose::error::CoseError;
use fdo_data_formats::{
    constants::MessageType,
    messages::{v10::ErrorMessage, ClientMessage, EncryptionRequirement, Message, ServerMessage},
    ProtocolVersion, Serializable,
};

use crate::EncryptionKeys;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptographic error encrypting/decrypting")]
    Crypto(#[from] CoseError),
    #[error("Error parsing or generating request")]
    Parse(#[from] fdo_data_formats::messages::ParseError),
    #[error("Data format error: {0}")]
    DataFormat(#[from] fdo_data_formats::Error),
    #[error("Error performing request")]
    Request(#[from] reqwest::Error),
    #[error("Missing message type in response")]
    MissingMessageType,
    #[error("Invalid message type {0} encountered")]
    InvalidMessageType(String),
    #[error("Invalid message type {0:?} encountered, expected {1:?}")]
    InvalidMessage(MessageType, MessageType),
    #[error("Error returned by server: {0:?}")]
    Error(ErrorMessage),
    #[error("Request message encryption requirement not met: {0:?}")]
    RequestEncryptionNotSatisfied(EncryptionRequirement),
    #[error("Response message encryption requirement not met: {0:?}")]
    ResponseEncryptionNotSatisfied(EncryptionRequirement),
    #[error("Programming error: invalid message sequence for request")]
    InvalidSequenceRequest,
    #[error("Programming error: invalid message sequence for expected response")]
    InvalidSequenceResponse,
}

pub type RequestResult<MT> = Result<MT, Error>;

#[derive(Debug)]
pub struct ServiceClient {
    protocol_version: ProtocolVersion,
    base_url: String,
    client: reqwest::Client,
    authorization_token: Option<String>,
    encryption_keys: EncryptionKeys,
    last_message_type: Option<MessageType>,
}

impl ServiceClient {
    pub fn new(protocol_version: ProtocolVersion, base_url: &str) -> Self {
        ServiceClient {
            protocol_version,
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            authorization_token: None,
            encryption_keys: EncryptionKeys::unencrypted(),
            last_message_type: None,
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
        if !OM::is_valid_previous_message(self.last_message_type) {
            return Err(Error::InvalidSequenceRequest);
        }
        if !SM::is_valid_previous_message(Some(OM::message_type())) {
            return Err(Error::InvalidSequenceResponse);
        }
        self.last_message_type = Some(SM::message_type());

        if let Some(req_enc_requirement) = OM::encryption_requirement() {
            if req_enc_requirement == EncryptionRequirement::MustBeEncrypted
                && self.encryption_keys.is_none()
            {
                return Err(Error::RequestEncryptionNotSatisfied(req_enc_requirement));
            }
            if req_enc_requirement == EncryptionRequirement::MustNotBeEncrypted
                && self.encryption_keys.is_some()
            {
                return Err(Error::RequestEncryptionNotSatisfied(req_enc_requirement));
            }
        }
        if let Some(resp_enc_requirement) = SM::encryption_requirement() {
            let is_response_encrypted = self.encryption_keys.is_some() || new_keys.is_some();
            if resp_enc_requirement == EncryptionRequirement::MustBeEncrypted
                && !is_response_encrypted
            {
                return Err(Error::ResponseEncryptionNotSatisfied(resp_enc_requirement));
            }
            if resp_enc_requirement == EncryptionRequirement::MustNotBeEncrypted
                && is_response_encrypted
            {
                return Err(Error::ResponseEncryptionNotSatisfied(resp_enc_requirement));
            }
        }

        let to_send = to_send.serialize_data()?;
        let to_send = self.encryption_keys.encrypt(&to_send)?;
        log::trace!("Sending message: {:?}", hex::encode(&to_send));

        let url = format!(
            "{}/fdo/{}/msg/{}",
            &self.base_url,
            self.protocol_version,
            OM::message_type() as u8
        );

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(to_send);

        if let Some(authorization_token) = &self.authorization_token {
            req = req.header("Authorization", authorization_token);
        }

        if !fdo_data_formats::INTEROPERABLE_KDF {
            req = req.header("X-Non-Interoperable-KDF", "true");
        }

        if let Some(new_keys) = new_keys {
            self.encryption_keys = new_keys;
        }

        let resp = req.send().await?;

        let msgtype = resp
            .headers()
            .get("message-type")
            .map(reqwest::header::HeaderValue::to_str)
            .transpose()
            .map_err(|_| Error::InvalidMessageType("non-string".to_string()))?;
        let msgtype = msgtype
            .map(u8::from_str)
            .transpose()
            .map_err(|_| Error::InvalidMessageType(msgtype.unwrap().to_string()))?
            .map(MessageType::try_from)
            .transpose()
            .map_err(|_| Error::InvalidMessageType(msgtype.unwrap().to_string()))?;
        let msgtype = match msgtype {
            Some(msgtype) => msgtype,
            None => {
                if resp.status().is_success() {
                    return Err(Error::MissingMessageType);
                } else {
                    MessageType::Error
                }
            }
        };

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
        log::trace!("Received: {:?}", hex::encode(&resp));

        if is_success {
            let resp = self.encryption_keys.decrypt(&resp)?;
            Ok(SM::deserialize_data(&resp)?)
        } else {
            Err(Error::Error(ErrorMessage::deserialize_data(&resp)?))
        }
    }
}
