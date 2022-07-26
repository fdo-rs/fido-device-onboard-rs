use std::collections::HashMap;

use openssl::{hash::MessageDigest, pkey::PKeyRef, x509::X509};
use serde_cbor::value::from_value;

use crate::{
    constants::{RendezvousProtocolValue, RendezvousVariable},
    publickey::PublicKey,
    types::{CborSimpleType, Hash, IPAddress, RendezvousDirective, RendezvousInfo},
    Error, Serializable,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RendezvousInterpreterSide {
    Device,
    Owner,
}

#[derive(Debug)]
pub struct RendezvousInterpretedDirective {
    pub ip_addresses: Option<Vec<IPAddress>>,
    pub dns_name: Option<String>,
    pub port: u32,

    pub server_certificate_hash: Option<Hash>,
    pub ca_certificate_hash: Option<Hash>,

    pub user_input: bool,

    pub wifi_ssid: Option<String>,
    pub wifi_password: Option<String>,

    pub medium: Option<u8>,
    pub protocol: RendezvousProtocolValue,

    pub delay: u32,

    pub bypass: bool,
}

impl RendezvousInterpretedDirective {
    pub fn get_urls(&self) -> Vec<String> {
        let protocol_text = match self.protocol {
            RendezvousProtocolValue::Http => "http",
            RendezvousProtocolValue::Https => "https",
            _ => return Vec::new(),
        };

        let mut urls = Vec::new();

        if let Some(dns_name) = &self.dns_name {
            urls.push(format!("{}://{}:{}", protocol_text, dns_name, self.port));
        }

        if let Some(ip_addresses) = self.ip_addresses.as_ref() {
            for ip_address in ip_addresses {
                urls.push(format!("{}://{}:{}", protocol_text, ip_address, self.port));
            }
        }

        urls
    }

    #[allow(clippy::ptr_arg)]
    fn from_rv_directive(
        info: &RendezvousDirective,
        side: RendezvousInterpreterSide,
    ) -> Result<Option<Self>, Error> {
        let mut ip_addresses = Vec::new();
        let mut dns_name = None;
        let mut port = None;
        let mut server_certificate_hash = None;
        let mut ca_certificate_hash = None;
        let mut user_input = false;
        let mut wifi_ssid = None;
        let mut wifi_password = None;
        let mut medium = None;
        let mut protocol = RendezvousProtocolValue::Tls;
        let mut delay = 0;
        let mut bypass = false;

        for (variable, value) in info {
            let value = CborSimpleType::deserialize_data(value)?;
            match variable {
                RendezvousVariable::DeviceOnly => {
                    if side != RendezvousInterpreterSide::Device {
                        return Ok(None);
                    }
                }
                RendezvousVariable::OwnerOnly => {
                    if side != RendezvousInterpreterSide::Owner {
                        return Ok(None);
                    }
                }
                RendezvousVariable::IPAddress => {
                    ip_addresses.push(from_value(value.clone())?);
                }
                RendezvousVariable::DevicePort => {
                    if side == RendezvousInterpreterSide::Device {
                        port = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::OwnerPort => {
                    if side == RendezvousInterpreterSide::Owner {
                        port = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::Dns => {
                    dns_name = Some(from_value(value.clone())?);
                }
                RendezvousVariable::ServerCertHash => {
                    if side == RendezvousInterpreterSide::Device {
                        server_certificate_hash = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::CaCertHash => {
                    if side == RendezvousInterpreterSide::Device {
                        ca_certificate_hash = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::UserInput => {
                    if side == RendezvousInterpreterSide::Device {
                        user_input = true;
                    }
                }
                RendezvousVariable::WifiSsid => {
                    if side == RendezvousInterpreterSide::Device {
                        wifi_ssid = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::WifiPw => {
                    if side == RendezvousInterpreterSide::Device {
                        wifi_password = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::Medium => {
                    if side == RendezvousInterpreterSide::Device {
                        medium = Some(from_value(value.clone())?);
                    }
                }
                RendezvousVariable::Protocol => {
                    protocol = from_value(value.clone())?;
                }
                RendezvousVariable::Delaysec => {
                    delay = from_value(value.clone())?;
                }
                RendezvousVariable::Bypass => {
                    if side == RendezvousInterpreterSide::Device {
                        bypass = true;
                    } else {
                        // No bypass possible on owner server
                        return Ok(None);
                    }
                }
            }
        }

        Ok(Some(RendezvousInterpretedDirective {
            ip_addresses: if ip_addresses.is_empty() {
                None
            } else {
                Some(ip_addresses)
            },
            dns_name,
            port: match port {
                Some(v) => v,
                None => match protocol.default_port() {
                    Some(v) => v,
                    None => {
                        return Err(<serde_cbor::Error as serde::de::Error>::missing_field(
                            "No default port",
                        )
                        .into())
                    }
                },
            },
            server_certificate_hash,
            ca_certificate_hash,
            user_input,
            wifi_ssid,
            wifi_password,
            medium,
            protocol,
            delay,
            bypass,
        }))
    }
}

impl RendezvousInfo {
    pub fn to_interpreted(
        &self,
        side: RendezvousInterpreterSide,
    ) -> Result<Vec<RendezvousInterpretedDirective>, Error> {
        self.values()
            .iter()
            .map(|v| RendezvousInterpretedDirective::from_rv_directive(v, side))
            .filter(|v| !matches!(v, Ok(None)))
            .map(|v| match v {
                Ok(v) => Ok(v.unwrap()),
                Err(e) => Err(e),
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct X509ValidationError;

impl<T: std::error::Error> From<T> for X509ValidationError {
    fn from(err: T) -> Self {
        log::warn!("Error encountered during X509 validation: {:?}", err);
        X509ValidationError
    }
}

#[derive(Debug, Default)]
pub struct X5Bag {
    certs: HashMap<Vec<u8>, X509>,
}

impl X5Bag {
    pub fn new() -> Self {
        X5Bag {
            certs: HashMap::new(),
        }
    }

    pub fn with_certs(certs: Vec<X509>) -> Result<Self, Error> {
        let mut bag = X5Bag {
            certs: HashMap::with_capacity(certs.len()),
        };

        for cert in certs {
            bag.add_cert(cert)?;
        }

        Ok(bag)
    }

    pub fn add_cert(&mut self, cert: X509) -> Result<(), Error> {
        let cert_digest = cert.digest(MessageDigest::sha256())?;
        self.certs.insert(cert_digest.to_vec(), cert);
        Ok(())
    }

    pub fn contains(&self, to_find: &X509) -> bool {
        let to_find_digest = match to_find.digest(MessageDigest::sha256()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        match self.certs.get_key_value(to_find_digest.as_ref()) {
            None => false,
            Some((digest, _)) => openssl::memcmp::eq(&to_find_digest, digest),
        }
    }

    pub fn contains_publickey(&self, to_find: &PublicKey) -> bool {
        self.contains_pkey(to_find.pkey())
    }

    pub fn contains_pkey<P>(&self, to_find: &PKeyRef<P>) -> bool
    where
        P: openssl::pkey::HasPublic,
    {
        for (_, cert) in self.certs.iter() {
            if cert.public_key().unwrap().public_eq(to_find) {
                return true;
            }
        }
        false
    }

    pub fn into_vec(mut self) -> Vec<X509> {
        self.certs.drain().map(|(_, v)| v).collect()
    }
}
