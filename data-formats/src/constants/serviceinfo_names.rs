use std::{fmt::Display, str::FromStr};

impl<'de> serde::Deserialize<'de> for ServiceInfoModule {
    fn deserialize<D>(deserializer: D) -> Result<ServiceInfoModule, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct SIMVisitor;
        impl serde::de::Visitor<'_> for SIMVisitor {
            type Value = ServiceInfoModule;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a module string")
            }

            fn visit_str<E>(self, value: &str) -> Result<ServiceInfoModule, E>
            where
                E: serde::de::Error,
            {
                ServiceInfoModule::from_str(value).map_err(|e| E::custom(format!("{e}")))
            }
        }
        deserializer.deserialize_string(SIMVisitor)
    }
}

impl serde::Serialize for ServiceInfoModule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceInfoModule {
    Standard(StandardServiceInfoModule),
    FedoraIot(FedoraIotServiceInfoModule),
    RedHatCom(RedHatComServiceInfoModule),
    Unsupported(String),
}

impl FromStr for ServiceInfoModule {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "org.fedoraiot.binaryfile" => FedoraIotServiceInfoModule::BinaryFile.into(),
            "org.fedoraiot.command" => FedoraIotServiceInfoModule::Command.into(),
            "org.fedoraiot.sshkey" => FedoraIotServiceInfoModule::SSHKey.into(),
            "org.fedoraiot.diskencryption-clevis" => {
                FedoraIotServiceInfoModule::DiskEncryptionClevis.into()
            }
            "org.fedoraiot.reboot" => FedoraIotServiceInfoModule::Reboot.into(),

            "com.redhat.subscriptionmanager" => {
                RedHatComServiceInfoModule::SubscriptionManager.into()
            }

            "devmod" => StandardServiceInfoModule::DevMod.into(),

            other => ServiceInfoModule::Unsupported(other.to_string()),
        })
    }
}

impl From<StandardServiceInfoModule> for ServiceInfoModule {
    fn from(module: StandardServiceInfoModule) -> Self {
        ServiceInfoModule::Standard(module)
    }
}

impl From<FedoraIotServiceInfoModule> for ServiceInfoModule {
    fn from(module: FedoraIotServiceInfoModule) -> Self {
        ServiceInfoModule::FedoraIot(module)
    }
}

impl From<RedHatComServiceInfoModule> for ServiceInfoModule {
    fn from(module: RedHatComServiceInfoModule) -> Self {
        ServiceInfoModule::RedHatCom(module)
    }
}

impl Display for ServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceInfoModule::Standard(module) => module.fmt(f),
            ServiceInfoModule::FedoraIot(module) => {
                write!(f, "org.fedoraiot.")?;
                Display::fmt(module, f)
            }
            ServiceInfoModule::RedHatCom(module) => {
                write!(f, "com.redhat.")?;
                Display::fmt(module, f)
            }
            ServiceInfoModule::Unsupported(other) => write!(f, "{other}"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardServiceInfoModule {
    DevMod,
}

impl Display for StandardServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                StandardServiceInfoModule::DevMod => "devmod",
            }
        )
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum FedoraIotServiceInfoModule {
    Command,
    SSHKey,
    BinaryFile,
    DiskEncryptionClevis,
    Reboot,
}

impl Display for FedoraIotServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FedoraIotServiceInfoModule::Command => "command",
                FedoraIotServiceInfoModule::SSHKey => "sshkey",
                FedoraIotServiceInfoModule::BinaryFile => "binaryfile",
                FedoraIotServiceInfoModule::DiskEncryptionClevis => "diskencryption-clevis",
                FedoraIotServiceInfoModule::Reboot => "reboot",
            }
        )
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedHatComServiceInfoModule {
    SubscriptionManager,
}

impl Display for RedHatComServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RedHatComServiceInfoModule::SubscriptionManager => "subscriptionmanager",
            }
        )
    }
}
