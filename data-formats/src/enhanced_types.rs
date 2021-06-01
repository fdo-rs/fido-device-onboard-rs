use std::net::IpAddr;

use openssl::x509::{X509Ref, X509VerifyResult, X509};
use serde_cbor::value::from_value;

use crate::{
    constants::{RendezvousProtocolValue, RendezvousVariable},
    publickey::{PublicKey, PublicKeyBody},
    types::{Hash, RendezvousDirective, RendezvousInfo},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RendezvousInterpreterSide {
    Device,
    Owner,
}

#[derive(Debug)]
pub struct RendezvousInterpretedDirective {
    pub ip_addresses: Option<Vec<IpAddr>>,
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
    ) -> Result<Option<Self>, serde_cbor::Error> {
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
                        // No bpyass possible on owner server
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
                None => protocol.default_port(),
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
    ) -> Result<Vec<RendezvousInterpretedDirective>, serde_cbor::Error> {
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

#[derive(Debug)]
pub struct X5Bag {
    trusted_certs: Vec<X509>,
}

impl X5Bag {
    pub fn new(trusted_certs: Vec<X509>) -> Self {
        X5Bag { trusted_certs }
    }

    fn build_chains(
        &self,
        under_consideration: &X509Ref,
        intermediates: &[X509],
    ) -> Result<Vec<Vec<X509>>, X509ValidationError> {
        let mut chains = Vec::new();

        // TODO: Possibly actually do chain building....
        // Let's for now assume that 'intermediates' is an x5chain, i.e. in order
        let mut chain = intermediates.to_vec();
        chain.insert(0, under_consideration.to_owned());

        chains.push(chain);

        Ok(chains)
    }

    fn validate_chain(&self, chain: &[X509]) -> Result<(), X509ValidationError> {
        log::trace!("Validating chain {:?}", chain);

        for (pos, entry) in chain.iter().enumerate() {
            if pos == chain.len() - 1 {
                // This is the last item, check if it's signed fully
                for trusted in &self.trusted_certs {
                    if trusted.issued(entry) == X509VerifyResult::OK {
                        let trusted_key = trusted.public_key()?;
                        match entry.verify(&trusted_key) {
                            Err(e) => return Err(X509ValidationError::from(e)),
                            Ok(false) => {
                                log::info!("Signature at pos {} invalid", pos);
                                return Err(X509ValidationError);
                            }
                            Ok(true) => return Ok(()),
                        }
                    }
                }
            } else {
                // This is an intermediate cert
                let signer = &chain[pos + 1];
                if signer.issued(entry) != X509VerifyResult::OK {
                    log::info!("Certificate at pos {} is not issued by next", pos);
                    return Err(X509ValidationError);
                }
                let signer_key = signer.public_key()?;
                match entry.verify(&signer_key) {
                    Err(e) => return Err(X509ValidationError::from(e)),
                    Ok(false) => {
                        log::info!("Signature at pos {} invalid", pos);
                        return Err(X509ValidationError);
                    }
                    Ok(true) => {}
                }
            }
        }

        log::warn!("Validation ended up at the very end without trusted cert");
        Err(X509ValidationError)
    }

    pub fn validate(
        &self,
        under_consideration: &PublicKey,
        intermediates: &[X509],
    ) -> Result<(), X509ValidationError> {
        let (_, under_consideration) = under_consideration
            .get_body()
            .map_err(X509ValidationError::from)?;
        let under_consideration = match under_consideration {
            PublicKeyBody::X509(cert) => cert,
            _ => {
                log::warn!("Non-x509 public keys not yet supported");
                return Err(X509ValidationError);
            }
        };

        for chain in self.build_chains(&under_consideration, intermediates)? {
            // Check signatures, build_chains only look sat the signers
            log::trace!("Checking possible chain");
            if self.validate_chain(&chain).is_ok() {
                return Ok(());
            }
        }

        log::info!("No valid chain found that is validly signed");
        Err(X509ValidationError)
    }
}
