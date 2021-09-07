use std::{convert::TryInto, fs};
use std::{env, str::FromStr};

use anyhow::{bail, Context, Result};

use fdo_data_formats::{
    constants::{HashType, HeaderKeys, KeyStorageType, MfgStringType, PublicKeyType},
    devicecredential::FileDeviceCredential,
    messages,
    publickey::{PublicKey, X5Chain},
    types::{
        CborSimpleType, CipherSuite, Guid, HMac, Hash, KexSuite, KeyDeriveSide, KeyExchange, Nonce,
        RendezvousInfo,
    },
    PROTOCOL_VERSION,
};
use fdo_http_wrapper::{
    client::{RequestResult, ServiceClient},
    EncryptionKeys,
};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};

const DEVICE_CREDENTIAL_FILESYSTEM_PATH: &str = "/etc/device-credentials";

async fn perform_diun(
    client: &mut ServiceClient,
    pub_key_verification: DiunPublicKeyVerificationMode,
) -> Result<(KeyReference, MfgStringType)> {
    log::info!("Performing DIUN");

    let nonce_diun_1 = Nonce::new().context("Error generating diun_nonce_1")?;
    let kexsuite = KexSuite::Ecdh384;
    let ciphersuite = CipherSuite::A256Gcm;
    let key_exchange = KeyExchange::new(kexsuite).context("Error initializing key exchange")?;

    // Send: Connect, Receive: Accept
    let accept: RequestResult<messages::diun::Accept> = client
        .send_request(
            messages::diun::Connect::new(
                nonce_diun_1.clone(),
                kexsuite,
                ciphersuite,
                key_exchange
                    .get_public()
                    .context("Error serializing public key exchange bit")?,
            ),
            None,
        )
        .await;
    let accept = accept.context("Error sending Connect")?.into_token();
    log::debug!("DIUN Accept token: {:?}", accept);
    let diun_pubchain = accept
        .get_unprotected_value::<X5Chain>(HeaderKeys::CUPHOwnerPubKey)
        .context("Error getting diun_pubkey")?
        .context("No DIUN public key provided")?;
    log::debug!("Validating DIUN public chain: {:?}", diun_pubchain);

    let diun_pubkey = match pub_key_verification {
        DiunPublicKeyVerificationMode::Hash(hash) => diun_pubchain.verify_from_digest(&hash),
        DiunPublicKeyVerificationMode::Insecure => {
            diun_pubchain.insecure_verify_without_root_verification()
        }
    }
    .context("Error getting DIUN leaf key")?;
    log::debug!("DIUN public key: {:?}", diun_pubkey);
    let diun_pubkey = diun_pubkey
        .public_key()
        .context("Error getting DIUN public key")?;

    let nonce_diun_1_from_server: Nonce = accept
        .get_protected_value(HeaderKeys::CUPHNonce, &diun_pubkey)
        .context("Error getting nonce from reply")?
        .context("No nonce provided by server")?;
    if nonce_diun_1 != nonce_diun_1_from_server {
        bail!("Nonce from server did not match challenge");
    }
    let accept_payload: messages::diun::AcceptPayload = accept
        .get_payload(&diun_pubkey)
        .context("Error parsing Accept payload")?;
    log::debug!("Accept payload: {:?}", accept_payload);
    let new_keys = key_exchange
        .derive_key(
            KeyDeriveSide::Device,
            ciphersuite,
            accept_payload.key_exchange(),
        )
        .context("Error performing key derivation")?;
    let new_keys = EncryptionKeys::from_derived(ciphersuite, new_keys);
    log::debug!("Derived new keys: {:?}", new_keys);

    let key_parameters: RequestResult<messages::diun::ProvideKeyParameters> = client
        .send_request(
            messages::diun::RequestKeyParameters::new(None),
            Some(new_keys),
        )
        .await;
    let key_parameters = key_parameters.context("Error requesting key parameters")?;
    log::debug!("Key parameters: {:?}", key_parameters);

    let key_ref = KeyReference::get_new_key(
        *key_parameters.key_type(),
        key_parameters.key_storage_types_allowed(),
    )
    .await
    .context("Error getting new key")?;

    let done: RequestResult<messages::diun::Done> = client
        .send_request(
            messages::diun::ProvideKey::new(
                key_ref
                    .get_public_key()
                    .context("Error getting public key from key reference")?,
                key_ref.get_public_key_storage_type(),
            ),
            None,
        )
        .await;
    let done = done.context("Error sending ProvideKey")?;

    Ok((key_ref, done.mfg_string_type()))
}

async fn perform_di(
    client: &mut ServiceClient,
    key_reference: KeyReference,
    mfg_string_type: MfgStringType,
) -> Result<()> {
    let mfg_info = get_mfg_info(mfg_string_type)
        .await
        .context("Error building MFG string")?;
    let set_credentials: RequestResult<messages::di::SetCredentials> = client
        .send_request(messages::di::AppStart::new(mfg_info), None)
        .await;
    let set_credentials = set_credentials.context("Error sending AppStart")?;
    let ov_header = set_credentials.into_ov_header();
    let ov_header_buf =
        serde_cbor::to_vec(&ov_header).context("Error serializing Ownership Voucher header")?;
    let ov_header_hmac = key_reference
        .perform_hmac(&ov_header_buf)
        .context("Error computing HMac over Ownership Voucher Header")?;

    key_reference
        .save_to_credential(
            ov_header.device_info,
            ov_header.guid,
            ov_header.rendezvous_info,
            ov_header.public_key,
        )
        .context("Error saving key reference to credential")?;

    let done: RequestResult<messages::di::Done> = client
        .send_request(messages::di::SetHMAC::new(ov_header_hmac), None)
        .await;
    done.context("Error sending SetHmac")?;

    Ok(())
}

#[derive(Debug)]
enum DiunPublicKeyVerificationMode {
    Hash(Hash),
    Insecure,
}

impl DiunPublicKeyVerificationMode {
    fn get_from_env() -> Result<Self> {
        if let Ok(_rootcerts) = env::var("DIUN_PUB_KEY_ROOTCERTS") {
            todo!()
        } else if let Ok(hash) = env::var("DIUN_PUB_KEY_HASH") {
            Ok(DiunPublicKeyVerificationMode::Hash(
                Hash::guess_new_from_data(
                    hex::decode(hash).context("DIUN_PUB_KEY_HASH is not valid hex")?,
                )
                .context("Error parsing DIUN_PUB_KEY_HASH as hash")?,
            ))
        } else if env::var("DIUN_PUB_KEY_INSECURE").is_ok() {
            Ok(DiunPublicKeyVerificationMode::Insecure)
        } else {
            bail!("No DIUN root key verification variables set")
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_http_wrapper::init_logging();

    let url = env::var("MANUFACTURING_SERVICE_URL")
        .context("Please provide MANUFACTURING_SERVICE_URL")?;
    let use_plain_di: bool = match env::var("USE_PLAIN_DI") {
        Ok(val) => val == "true",
        Err(_) => false,
    };

    let diun_pub_key_verification = if use_plain_di {
        DiunPublicKeyVerificationMode::Insecure
    } else {
        DiunPublicKeyVerificationMode::get_from_env()
            .context("Error determining how to verify DIUN public key")?
    };

    log::info!(
        "Attempting manufacturing, url: {}, plain DI: {}, DIUN public key verification: {:?}",
        url,
        use_plain_di,
        diun_pub_key_verification
    );

    let mut client = ServiceClient::new(&url);

    let (keyref, mfg_string_type) = if use_plain_di {
        let mfg_string_type =
            env::var("DI_MFG_STRING_TYPE").unwrap_or_else(|_| String::from("serialnumber"));
        let mfg_string_type = MfgStringType::from_str(&mfg_string_type).with_context(|| {
            format!("Unsupported MFG string type {} requested", &mfg_string_type)
        })?;

        let keyref = KeyReference::env_key()
            .await
            .context("Error determining key for DI")?;

        (keyref, mfg_string_type)
    } else {
        log::debug!("Performing DIUN");
        perform_diun(&mut client, diun_pub_key_verification)
            .await
            .context("Error performing DIUN")?
    };
    log::debug!(
        "Performing Device Initialization, with key reference {:?} and MFG String Type {:?}",
        &keyref,
        &mfg_string_type
    );

    perform_di(&mut client, keyref, mfg_string_type)
        .await
        .context("Error performing DI")
}

async fn get_mfg_info(mfg_string_type: MfgStringType) -> Result<CborSimpleType> {
    if let Some(mfg_info) = env::var_os("MANUFACTURING_INFO") {
        return Ok(CborSimpleType::Text(mfg_info.into_string().unwrap()));
    }
    match mfg_string_type {
        MfgStringType::SerialNumber => {
            let serial = fs::read_to_string("/sys/devices/virtual/dmi/id/product_serial")
                .or_else(|_| fs::read_to_string("/sys/devices/virtual/dmi/id/chassis_serial"))
                .context("Error determining system serial number")?;
            Ok(CborSimpleType::Text(serial))
        }
        _ => bail!(
            "Unsupported MFG string type {:?} requested",
            mfg_string_type
        ),
    }
}

#[derive(Debug)]
enum KeyReference {
    FileSystem {
        sign_key: PKey<Private>,
        hmac_key: PKey<Private>,
    },
}

impl KeyReference {
    async fn get_new_key_filesystem(keytype: PublicKeyType) -> Result<Self> {
        let mut hmac_key_buf = [0; 32];
        openssl::rand::rand_bytes(&mut hmac_key_buf).context("Error creating random HMAC key")?;
        let hmac_key_buf = hmac_key_buf;
        let hmac_key = PKey::hmac(&hmac_key_buf).context("Error building HMAC key")?;

        match keytype {
            PublicKeyType::SECP256R1 | PublicKeyType::SECP384R1 => {
                let curve_name = match keytype {
                    PublicKeyType::SECP256R1 => Nid::X9_62_PRIME256V1,
                    PublicKeyType::SECP384R1 => Nid::SECP384R1,
                    _ => unreachable!(),
                };
                let group =
                    EcGroup::from_curve_name(curve_name).context("Error getting curve group")?;
                let sign_key =
                    PKey::from_ec_key(EcKey::generate(&group).context("Error generating EC key")?)
                        .context("Error creating EC key")?;
                Ok(KeyReference::FileSystem { sign_key, hmac_key })
            }
            _ => bail!("Key type not supported"),
        }
    }

    async fn get_new_key(
        keytype: PublicKeyType,
        allowed_storage_types: Option<&[KeyStorageType]>,
    ) -> Result<Self> {
        let allowed_storage_types = match allowed_storage_types {
            Some(storage_types) if storage_types.is_empty() => {
                bail!("No key storage types allowed")
            }
            Some(storage_types) => storage_types,
            None => &[KeyStorageType::FileSystem],
        };
        for key_storage_type in allowed_storage_types {
            #[allow(clippy::single_match)]
            match *key_storage_type {
                KeyStorageType::FileSystem => {
                    return KeyReference::get_new_key_filesystem(keytype).await
                }
                _ => {}
            }
        }
        bail!(
            "No usable key storage types found, allowed: {:?}",
            allowed_storage_types
        );
    }

    async fn env_key_filesystem() -> Result<Self> {
        let sign_key_path = env::var("DI_SIGN_KEY_PATH").context("No DI sign key path set")?;
        let hmac_key_path = env::var("DI_HMAC_KEY_PATH").context("No DI HMAC key path set")?;

        let sign_key = fs::read(&sign_key_path)
            .with_context(|| format!("Error reading sign key from {}", &sign_key_path))?;
        let hmac_key = fs::read(&hmac_key_path)
            .with_context(|| format!("Error reading HMAC key from {}", &hmac_key_path))?;

        let sign_key = PKey::private_key_from_der(&sign_key).context("Error loading sign key")?;
        let hmac_key = PKey::hmac(&hmac_key).context("Error loading HMAC key")?;

        Ok(KeyReference::FileSystem { sign_key, hmac_key })
    }

    async fn env_key() -> Result<Self> {
        let key_storage_type =
            env::var("DI_KEY_STORAGE_TYPE").context("No DI key storage type selected")?;
        let key_storage_type =
            KeyStorageType::from_str(&key_storage_type).context("Invalid storage type")?;

        match key_storage_type {
            KeyStorageType::FileSystem => KeyReference::env_key_filesystem().await,
            _ => bail!("Unsupported key storage type {:?}", key_storage_type),
        }
    }

    fn get_public_key(&self) -> Result<PublicKey> {
        match self {
            KeyReference::FileSystem { sign_key, .. } => {
                sign_key.try_into().context("Error serializing public key")
            }
        }
    }

    fn get_public_key_storage_type(&self) -> KeyStorageType {
        match self {
            KeyReference::FileSystem { .. } => KeyStorageType::FileSystem,
        }
    }

    fn save_to_credential(
        self,
        device_info: String,
        guid: Guid,
        rvinfo: RendezvousInfo,
        manufacturer_public_key: PublicKey,
    ) -> Result<()> {
        match self {
            KeyReference::FileSystem { sign_key, hmac_key } => {
                let private_key = sign_key
                    .private_key_to_der()
                    .context("Error serializing private sign key")?;
                let hmac_secret = hmac_key
                    .raw_private_key()
                    .context("Error serializing HMac key")?;
                let manufacturer_pubkey_hash = Hash::new(
                    None,
                    &serde_cbor::to_vec(&manufacturer_public_key)
                        .context("Error serializing manufacturer public key")?,
                )
                .context("Error hashing manufacturer public key")?;

                let cred = FileDeviceCredential {
                    active: true,
                    protver: PROTOCOL_VERSION,
                    hmac_secret,
                    device_info,
                    guid,
                    rvinfo,
                    pubkey_hash: manufacturer_pubkey_hash,
                    private_key,
                };

                let cred =
                    serde_cbor::to_vec(&cred).context("Error serializing device credential")?;

                let filename = match env::var_os("DEVICE_CREDENTIAL_FILENAME") {
                    Some(filename) => filename.into_string().unwrap(),
                    None => DEVICE_CREDENTIAL_FILESYSTEM_PATH.to_string(),
                };

                fs::write(filename, &cred).context("Error writing device credential")
            }
        }
    }

    fn perform_hmac(&self, data: &[u8]) -> Result<HMac> {
        match self {
            KeyReference::FileSystem { hmac_key, .. } => {
                let mut hmac_signer = Signer::new(MessageDigest::sha384(), hmac_key)
                    .context("Error creating hmac signer")?;
                hmac_signer
                    .update(data)
                    .context("Error feeding data to hmac computation")?;
                let hmac = hmac_signer
                    .sign_to_vec()
                    .context("Error finalizing hmac computation")?;
                Ok(HMac::new_from_data(HashType::Sha384, hmac))
            }
        }
    }
}
