use serde_derive::{Deserialize, Serialize};

use config::Config;

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub db_host: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            db_host: String::from("default"),
        }
    }
}

#[test]
fn set_defaults() {
    let c = Config::default();
    let s: Settings = c.try_deserialize().expect("Deserialization failed");

    assert_eq!(s.db_host, "default");
}

#[test]
fn try_from_defaults() {
    let c = Config::try_from(&Settings::default()).expect("Serialization failed");
    let s: Settings = c.try_deserialize().expect("Deserialization failed");
    assert_eq!(s.db_host, "default");
}
