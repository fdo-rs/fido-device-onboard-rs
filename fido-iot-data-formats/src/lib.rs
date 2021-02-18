mod errors;
pub use errors::Error;

const PROTOCOL_MAJOR_VERSION: u16 = 1;
const PROTOCOL_MINOR_VERSION: u16 = 0;
const PROTOCOL_VERSION: u16 = (PROTOCOL_MAJOR_VERSION * 100) + PROTOCOL_MINOR_VERSION;

mod constants;
pub use constants::{DeviceSigType, HashType};

mod types;
pub use types::{Hash, SigInfo};

mod ownershipvoucher;
mod publickey;
