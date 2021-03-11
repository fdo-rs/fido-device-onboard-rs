use serde::{Serialize, Deserialize};
use serde_tuple::{Serialize_tuple, Deserialize_tuple};

#[derive(Deserialize)]
struct Empty {}

#[derive(Debug, Serialize_tuple, Deserialize)]
struct Message {
    testa: u16,
    testb: u16,
    testc: String,
}

fn main() {
    // Derived: Ok([163, 101, 116, 101, 115, 116, 97, 24, 42, 101, 116, 101, 115, 116, 98, 16, 101, 116, 101, 115, 116, 99, 106, 72, 101, 108, 108, 111, 32, 99, 98, 111, 114])
    let test = Message {
        testa: 42,
        testb: 16,
        testc: String::from("Hello cbor"),
    };

    let encoded = serde_cbor::to_vec(&test).expect("Failed to encode");

    println!("Encoded: {:?}", &encoded);

    let decoded: Message = serde_cbor::from_slice(&encoded).expect("Error decoding");
    println!("Decoded: {:?}", decoded);
}
