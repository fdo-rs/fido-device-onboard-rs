//! Please note that the structures in this module are not stable

pub mod manufacturing_server;
pub mod owner_onboarding_server;
pub mod rendezvous_server;
pub mod serviceinfo_api_server;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Bind(SocketAddr);

impl Bind {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl Serialize for Bind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Bind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom("bind is empty".to_string()));
        }
        let parsed = s.parse::<SocketAddr>();
        parsed
            .map(Bind)
            .map_err(|e| serde::de::Error::custom(format!("Error parsing bind string: {e:?}")))
    }
}

impl std::fmt::Display for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl AsRef<SocketAddr> for Bind {
    fn as_ref(&self) -> &SocketAddr {
        &self.0
    }
}

impl From<Bind> for SocketAddr {
    fn from(bind: Bind) -> Self {
        bind.0
    }
}

#[derive(Debug)]
pub struct AbsolutePathBuf(PathBuf);

impl AbsolutePathBuf {
    pub fn new(path: PathBuf) -> Option<Self> {
        if !path.is_absolute() {
            None
        } else {
            Some(Self(path))
        }
    }
}

impl Serialize for AbsolutePathBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string_lossy())
    }
}

impl<'de> Deserialize<'de> for AbsolutePathBuf {
    fn deserialize<D>(deserializer: D) -> Result<AbsolutePathBuf, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom("path is empty".to_string()));
        }
        let path = PathBuf::from(&s);
        if !path.is_absolute() {
            return Err(serde::de::Error::custom(format!(
                "path {s} is not absolute"
            )));
        }
        Ok(AbsolutePathBuf(path))
    }
}

impl std::fmt::Display for AbsolutePathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl AsRef<Path> for AbsolutePathBuf {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
