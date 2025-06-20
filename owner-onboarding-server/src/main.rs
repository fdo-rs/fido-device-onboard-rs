use std::convert::{TryFrom, TryInto};
use std::fs;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use fdo_data_formats::constants::HashType;
use fdo_data_formats::enhanced_types::RendezvousInterpreterSide;
use fdo_data_formats::types::{COSESign, Hash, TO0Data, TO1DataPayload};
use fdo_data_formats::{messages, ProtocolVersion, Serializable};
use fdo_http_wrapper::client::RequestResult;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Builder, X509NameBuilder, X509},
};
use serde_bytes::ByteBuf;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    enhanced_types::X5Bag,
    ownershipvoucher::OwnershipVoucher,
    publickey::PublicKey,
    types::{Guid, TO2AddressEntry},
};

use fdo_store::{Store, StoreConfig, StoreError};
use fdo_util::servers::{
    configuration::{
        owner_onboarding_server::OwnerOnboardingServerSettings,
        owner_onboarding_server::DEFAULT_REGISTRATION_PERIOD,
        owner_onboarding_server::DEFAULT_RE_REGISTRATION_WINDOW, AbsolutePathBuf,
    },
    settings_for, OwnershipVoucherStoreMetadataKey,
};

mod handlers;

pub(crate) struct OwnerServiceUD {
    // Trusted keys
    trusted_device_keys: Option<X5Bag>,

    // Stores
    ownership_voucher_store: Box<
        dyn Store<
            fdo_store::ReadWriteOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    >,
    session_store: Arc<fdo_http_wrapper::server::SessionStore>,

    // Our keys
    owner_key: PKey<Private>,
    owner_pubkey: PublicKey,

    // The new Owner2Key, randomly generated, but not stored
    owner2_key: PKey<Private>,
    owner2_pub: PublicKey,

    // ServiceInfo API server configuration
    service_info_api_client: fdo_http_wrapper::client::JsonClient,

    owner_addresses: Vec<TO2AddressEntry>,

    // How much time (s) OVs are going to be registered
    ov_registration_period: u32,
    // The time window (s) within which the re-registration will start
    ov_re_registration_window: u32,

    window_check_enabled: bool,
}

pub(crate) type OwnerServiceUDT = Arc<OwnerServiceUD>;

fn load_private_key(path: &AbsolutePathBuf) -> Result<PKey<Private>> {
    let contents = fs::read(path)?;
    Ok(PKey::private_key_from_der(&contents)?)
}

async fn _handle_report_to_rendezvous(udt: &OwnerServiceUDT, ov: &OwnershipVoucher) -> Result<()> {
    match report_ov_to_rendezvous(
        ov,
        &udt.owner_addresses,
        &udt.owner_key,
        udt.ov_registration_period,
        &udt.trusted_device_keys,
    )
    .await
    {
        Ok(wait_seconds) => {
            udt.ownership_voucher_store
                .store_metadata(
                    ov.header().guid(),
                    &fdo_store::MetadataKey::Local(
                        OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds,
                    ),
                    &time::Duration::new(wait_seconds.into(), 0),
                )
                .await?;
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "OV({}): failed to report to rendezvous: {}",
                ov.header().guid().to_string(),
                e
            );
            Ok(())
        }
    }
}

async fn report_to_rendezvous(udt: OwnerServiceUDT) -> Result<()> {
    // TODO: this below (query_data vs query_ovs_db) should be abstracted into the store's Filter's query stuff
    match udt.ownership_voucher_store.query_data().await {
        Ok(mut ft) => {
            ft.neq(
                &fdo_store::MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed),
                &true,
            );
            ft.lt(
                &fdo_store::MetadataKey::Local(
                    OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds,
                ),
                time::OffsetDateTime::now_utc().unix_timestamp(),
            );
            let ov_iter = ft.query().await?;
            if let Some(ovs) = ov_iter {
                for ov in ovs {
                    _handle_report_to_rendezvous(&udt, &ov).await?;
                }
            }
        }
        Err(StoreError::MethodNotAvailable) => {
            match udt.ownership_voucher_store.query_ovs_db().await {
                Ok(ovs) => {
                    for ov in ovs {
                        _handle_report_to_rendezvous(&udt, &ov).await?
                    }
                }
                Err(StoreError::Unspecified(txt)) => {
                    log::warn!("DB error: {txt:?}")
                }
                Err(StoreError::MethodNotAvailable) => bail!("Unreachable"),
                Err(e) => {
                    log::warn!("DB error: {e:?}")
                }
            }
        }
        Err(e) => log::warn!("Error querying data: {e:?}"),
    };
    Ok(())
}

async fn check_registration_window(udt: &OwnerServiceUDT) -> Result<()> {
    let now_plus_window =
        time::OffsetDateTime::now_utc().unix_timestamp() + (udt.ov_re_registration_window as i64);
    // these are the ovs whose registration time will end and we need to
    // re-register them
    let ovs = udt
        .ownership_voucher_store
        .query_ovs_db_to2_performed_to0_less_than(false, now_plus_window)
        .await?;
    for ov in ovs {
        match report_ov_to_rendezvous(
            &ov,
            &udt.owner_addresses,
            &udt.owner_key,
            udt.ov_registration_period,
            &udt.trusted_device_keys,
        )
        .await
        {
            Ok(wait_seconds) => {
                udt.ownership_voucher_store
                    .store_metadata(
                        ov.header().guid(),
                        &fdo_store::MetadataKey::Local(
                            OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds,
                        ),
                        &time::Duration::new(wait_seconds.into(), 0),
                    )
                    .await?;
                if wait_seconds != udt.ov_registration_period {
                    log::warn!("OV({}): registered by rendezvous for {wait_seconds}s, as opposed to the requested {}s",
                               ov.header().guid().to_string(), udt.ov_registration_period);
                    if udt.ov_re_registration_window >= wait_seconds {
                        log::warn!("OV({}): re-registration won't be triggered (window: {}s, registration: {}s)",
                        ov.header().guid().to_string(), udt.ov_re_registration_window, udt.ov_registration_period);
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "OV({}): failed to report to rendezvous: {e}",
                    ov.header().guid().to_string()
                );
            }
        }
    }
    Ok(())
}

async fn report_ov_to_rendezvous(
    ov: &OwnershipVoucher,
    owner_addresses: &[TO2AddressEntry],
    owner_key: &PKey<Private>,
    registration_period: u32,
    trusted_device_keys: &Option<X5Bag>,
) -> Result<u32> {
    let ov_header = ov.header();
    if ov_header.protocol_version() != ProtocolVersion::Version1_1 {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version(),
            ProtocolVersion::Version1_1
        );
    }

    match ov.device_certificate_chain() {
        None => {
            bail!("No device certificate chain found");
        }
        Some(device_cert_chain) => {
            if let Some(trusted_device_keys) = trusted_device_keys {
                device_cert_chain
                    .verify_from_x5bag(trusted_device_keys)
                    .context("Device certificate is not trusted")?
            } else {
                device_cert_chain
                    .insecure_verify_without_root_verification()
                    .context("Device certificate chain is malformed")?
            };
        }
    };

    // Determine the RV IP
    let rv_info = ov_header
        .rendezvous_info()
        .to_interpreted(RendezvousInterpreterSide::Owner)
        .context("Error parsing rendezvous directives")?;
    if rv_info.is_empty() {
        bail!("No rendezvous information found that's usable for the owner");
    }
    for rv_directive in rv_info {
        let rv_urls = rv_directive.get_urls();
        if rv_urls.is_empty() {
            log::info!(
                "No usable rendezvous URLs were found for RV directive: {:?}",
                rv_directive
            );
            continue;
        }

        for rv_url in rv_urls {
            log::info!(
                "OV({}): Using rendezvous server at url {}",
                ov_header.guid().to_string(),
                rv_url
            );

            let mut rv_client =
                fdo_http_wrapper::client::ServiceClient::new(ProtocolVersion::Version1_1, &rv_url);

            // Send: Hello, Receive: HelloAck
            let hello_ack: RequestResult<messages::v11::to0::HelloAck> = rv_client
                .send_request(messages::v11::to0::Hello::new(), None)
                .await;

            let hello_ack = match hello_ack {
                Ok(hello_ack) => hello_ack,
                Err(e) => {
                    log::info!("Error requesting nonce from rendezvous server: {:?}", e);
                    continue;
                }
            };

            // Build to0d and to1d
            let to0d = TO0Data::new(ov.clone(), registration_period, hello_ack.nonce3().clone())
                .context("Error creating to0d")?;
            let to0d_vec = to0d.serialize_data().context("Error serializing TO0Data")?;
            let to0d_hash =
                Hash::from_data(HashType::Sha384, &to0d_vec).context("Error hashing to0d")?;
            let to0d = ByteBuf::from(to0d_vec);
            let to1d_payload = TO1DataPayload::new(Vec::from(owner_addresses), to0d_hash);
            let to1d =
                COSESign::new(&to1d_payload, None, owner_key).context("Error signing to1d")?;
            // Send: OwnerSign, Receive: AcceptOwner
            let msg = messages::v11::to0::OwnerSign::new(to0d, to1d)
                .context("Error creating OwnerSign message")?;
            let accept_owner: RequestResult<messages::v11::to0::AcceptOwner> =
                rv_client.send_request(msg, None).await;
            let accept_owner =
                accept_owner.context("Error registering self to rendezvous server")?;

            // Done!
            log::info!(
                "OV({}): Rendezvous server registered us for {} seconds",
                ov_header.guid().to_string(),
                accept_owner.wait_seconds()
            );

            return Ok(accept_owner.wait_seconds());
        }
    }
    bail!("Report to rendezvous not performed");
}

const MAINTENANCE_INTERVAL: u64 = 60;

async fn perform_maintenance(udt: OwnerServiceUDT) -> std::result::Result<(), &'static str> {
    log::info!(
        "Scheduling maintenance every {} seconds",
        MAINTENANCE_INTERVAL
    );

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(MAINTENANCE_INTERVAL)).await;

        let ov_maint = udt.ownership_voucher_store.perform_maintenance();
        let ses_maint = udt.session_store.perform_maintenance();
        let rtr_maint = report_to_rendezvous(udt.clone());

        #[allow(unused_must_use)]
        let (ov_res, ses_res, rtr_res) = tokio::join!(ov_maint, ses_maint, rtr_maint);

        if udt.window_check_enabled {
            let window_res = check_registration_window(&udt.clone()).await;
            if let Err(e) = window_res {
                log::warn!("Error during re-registration window check: {e:?}");
            }
        }

        if let Err(e) = ov_res {
            log::warn!("Error during ownership voucher store maintenance: {e:?}");
        }
        if let Err(e) = ses_res {
            log::warn!("Error during session store maintenance: {e:?}");
        }
        if let Err(e) = rtr_res {
            log::warn!("Error during report to rendezvous maintenance: {e:?}")
        }
    }
}

/// Generate an ephemeral owner2 key: we do not support reuse or resale protocols
fn generate_owner2_keys() -> Result<(PKey<Private>, PublicKey)> {
    let owner2_key_group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("Error getting nist 256 group")?;
    let owner2_key = EcKey::generate(&owner2_key_group).context("Error generating owned2 key")?;
    let owner2_key =
        PKey::from_ec_key(owner2_key).context("Error converting owner2 key to PKey")?;

    // Create an ephemeral certificate
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", "Ephemeral Owner2 Key")?;
    let subject = subject.build();

    let serial = BigNum::from_u32(42)?;
    let serial = Asn1Integer::from_bn(&serial)?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_issuer_name(&subject)?;
    builder.set_subject_name(&subject)?;
    builder.set_pubkey(&owner2_key)?;
    builder.set_serial_number(&serial)?;
    builder.sign(&owner2_key, MessageDigest::sha384())?;

    let owner2_cert = builder.build();

    let pubkey =
        PublicKey::try_from(owner2_cert).context("Error converting ephemeral owner2 key to PK")?;

    Ok((owner2_key, pubkey))
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    if !fdo_data_formats::interoperable_kdf_available()
        && std::env::var("ALLOW_NONINTEROPERABLE_KDF").is_err()
    {
        bail!("Provide environment ALLOW_NONINTEROPERABLE_KDF=1 to enable interoperable KDF");
    }

    let settings: OwnerOnboardingServerSettings = settings_for("owner-onboarding-server")?
        .try_deserialize()
        .context("Error parsing configuration")?;

    // Bind information
    let bind_addr = settings.bind.clone();

    // Load trusted CA certs for device certificate chain verification
    let trusted_device_keys = settings
        .trusted_device_keys_path
        .as_ref()
        .map(|path| -> Result<X5Bag, anyhow::Error> {
            let trusted_device_keys = {
                let contents = std::fs::read(path)
                    .with_context(|| format!("Error reading trusted device keys at {}", &path))?;
                X509::stack_from_pem(&contents).context("Error parsing trusted device keys")?
            };

            X5Bag::with_certs(trusted_device_keys)
                .context("Error building trusted device keys X5Bag")
        })
        .transpose()
        .context("Error loading trusted device keys")?;

    // Our private key
    let owner_key = load_private_key(&settings.owner_private_key_path).with_context(|| {
        format!(
            "Error loading owner key from {}",
            &settings.owner_private_key_path
        )
    })?;
    let owner_pubkey = {
        let contents = std::fs::read(&settings.owner_public_key_path).with_context(|| {
            format!(
                "Error reading owner public key from {}",
                &settings.owner_public_key_path
            )
        })?;
        PublicKey::try_from(X509::from_pem(&contents).context("Error parsing owner public key")?)
            .context("Error converting owner public key to PK")?
    };

    // Voucher registration times
    let ov_registration_period = match settings.ov_registration_period {
        Some(value) => {
            if value == 0 {
                bail!("ov_registration_period cannot be 0");
            }
            value
        }
        None => {
            log::info!(
                "Setting a default ov_registration_period of {DEFAULT_REGISTRATION_PERIOD} seconds"
            );
            DEFAULT_REGISTRATION_PERIOD
        }
    };
    let ov_re_registration_window = match settings.ov_re_registration_window {
        Some(value) => {
            if value == 0 {
                bail!("ov_re_registration_window cannot be 0");
            } else if value as u64 <= MAINTENANCE_INTERVAL {
                bail!("this server performs checks every {MAINTENANCE_INTERVAL} seconds, please specify an ov_re_registration_window larger than that value");
            }
            value
        }
        None => {
            log::info!("Setting a default ov_re_registration_window of {DEFAULT_RE_REGISTRATION_WINDOW} seconds");
            DEFAULT_RE_REGISTRATION_WINDOW
        }
    };

    if ov_re_registration_window >= ov_registration_period {
        bail!(
            "ov_re_registration_window ({ov_re_registration_window}) must be smaller than ov_registration_period ({ov_registration_period})");
    } else {
        log::info!("Server configured with an OV registration period of {ov_registration_period} seconds, OV re-registration window set to {ov_re_registration_window} seconds")
    }

    // Initialize stores
    let ownership_voucher_store = settings
        .ownership_voucher_store_driver
        .initialize()
        .context("Error initializing ownership voucher datastore")?;
    let session_store = settings
        .session_store_driver
        .initialize()
        .context("Error initializing session store")?;

    // the re-registration check is only available with DB store drivers
    let window_check_enabled = match settings.ownership_voucher_store_driver {
        StoreConfig::Directory { path: _ } => {
            log::info!("OV re-registration window check disabled, this feature is only available with DB storage drivers");
            false
        }
        _ => true,
    };

    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);

    // Generate a new Owner2
    let (owner2_key, owner2_pub) =
        generate_owner2_keys().context("Error generating new owner2 keys")?;

    let mut owner_addresses: Vec<TO2AddressEntry> = Vec::new();
    for oa in settings.owner_addresses {
        let address_entries: Vec<TO2AddressEntry> = oa.try_into()?;
        for ae in address_entries {
            owner_addresses.push(ae);
        }
    }

    // ServiceInfo API client
    let service_info_api_client = fdo_http_wrapper::client::JsonClient::new(
        settings.service_info_api_url,
        settings.service_info_api_authentication,
    )
    .context("Error generating serviceinfo API server")?;

    // Initialize user data
    let user_data = Arc::new(OwnerServiceUD {
        // Stores
        ownership_voucher_store,
        session_store: session_store.clone(),

        // Trusted keys
        trusted_device_keys,

        // Private owner key
        owner_key,
        owner_pubkey,

        // Ephemeral owner2 key
        owner2_key,
        owner2_pub,

        // Service Info
        service_info_api_client,

        // Owner addresses
        owner_addresses,

        // OV registration times
        ov_registration_period,
        ov_re_registration_window,

        window_check_enabled,
    });

    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the owner onboarding service");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    let ud = user_data.clone();
    let handler_import = warp::post()
        .and(warp::path("import"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::bytes())
        .map(move |bytes: bytes::Bytes| (ud.clone(), bytes))
        .untuple_one()
        .and_then(handlers::handler_import);

    // TO2
    let handler_to2_hello_device = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::hello_device,
    );
    let handler_to2_get_ov_next_entry = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::get_ov_next_entry,
    );
    let handler_to2_prove_device = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::prove_device,
    );
    let handler_to2_device_service_info_ready = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::device_service_info_ready,
    );
    let handler_to2_device_service_info = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::device_service_info,
    );
    let handler_to2_done = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::done,
    );

    let rtr_enabled = settings.report_to_rendezvous_endpoint_enabled;
    let ud = user_data.clone();
    let handler_report_to_rendezvous = warp::path("report-to-rendezvous")
        .and(warp::post())
        .and(warp::any().map(move || (ud.clone(), rtr_enabled)))
        .untuple_one()
        .and_then(handlers::report_to_rendezvous_handler);

    let routes = warp::post()
        .and(
            hello
                .or(handler_ping)
                .or(handler_report_to_rendezvous)
                // TO2
                .or(handler_to2_hello_device)
                .or(handler_to2_get_ov_next_entry)
                .or(handler_to2_prove_device)
                .or(handler_to2_device_service_info_ready)
                .or(handler_to2_device_service_info)
                .or(handler_to2_done),
        )
        .or(handler_import) // TODO(runcom): needs authentication with API key at least!
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("owner-onboarding-service"));

    log::info!("Listening on {}", bind_addr);
    let server = warp::serve(routes);

    let maintenance_runner =
        tokio::spawn(async move { perform_maintenance(user_data.clone()).await });

    let server = server
        .bind_with_graceful_shutdown(bind_addr, async {
            signal(SignalKind::terminate()).unwrap().recv().await;
            log::info!("Terminating");
        })
        .1;
    let server = tokio::spawn(server);

    tokio::select!(
    _ = server => {
        log::info!("Server terminated");
    },
    _ = maintenance_runner => {
        log::info!("Maintenance runner terminated");
    });

    Ok(())
}
