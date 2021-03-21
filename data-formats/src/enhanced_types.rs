use std::net::IpAddr;

use serde_cbor::value::from_value;

use crate::{
    constants::{RendezvousProtocolValue, RendezvousVariable},
    types::{Hash, RendezvousDirective, RendezvousInfo},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RendezvousInterpreterSide {
    Device,
    Owner,
}

#[derive(Debug)]
pub struct RendezvousInterpretedDirective {
    ip_addresses: Option<Vec<IpAddr>>,
    dns_name: Option<String>,
    port: u32,

    server_certificate_hash: Option<Hash>,
    ca_certificate_hash: Option<Hash>,

    user_input: bool,

    wifi_ssid: Option<String>,
    wifi_password: Option<String>,

    medium: Option<u8>,
    protocol: RendezvousProtocolValue,

    delay: u32,

    bypass: bool,
}

impl RendezvousInterpretedDirective {
    pub fn get_urls(&self) -> Vec<String> {
        let protocol_text = match self.protocol {
            RendezvousProtocolValue::HTTP => "http",
            RendezvousProtocolValue::HTTPS => "https",
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
        let mut protocol = RendezvousProtocolValue::TLS;
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
            .filter(|v| match v {
                Ok(None) => false,
                _ => true,
            })
            .map(|v| match v {
                Ok(v) => Ok(v.unwrap()),
                Err(e) => Err(e),
            })
            .collect()
    }
}
