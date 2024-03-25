#![cfg(feature = "ini")]

use serde_derive::Deserialize;

use std::path::PathBuf;

use config::{Config, File, FileFormat};

#[derive(Debug, Deserialize, PartialEq)]
struct Place {
    name: String,
    longitude: f64,
    latitude: f64,
    favorite: bool,
    reviews: u64,
    rating: Option<f32>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Settings {
    debug: f64,
    place: Place,
}

fn make() -> Config {
    Config::builder()
        .add_source(File::new("tests/Settings", FileFormat::Ini))
        .build()
        .unwrap()
}

#[test]
fn test_file() {
    let c = make();
    let s: Settings = c.try_deserialize().unwrap();
    assert_eq!(
        s,
        Settings {
            debug: 1.0,
            place: Place {
                name: String::from("Torre di Pisa"),
                longitude: 43.722_498_5,
                latitude: 10.397_052_2,
                favorite: false,
                reviews: 3866,
                rating: Some(4.5),
            },
        }
    );
}

#[test]
fn test_error_parse() {
    let res = Config::builder()
        .add_source(File::new("tests/Settings-invalid", FileFormat::Ini))
        .build();

    let path: PathBuf = ["tests", "Settings-invalid.ini"].iter().collect();

    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().to_string(),
        format!(
            r#"2:0 expecting "[Some('='), Some(':')]" but found EOF. in {}"#,
            path.display()
        )
    );
}
