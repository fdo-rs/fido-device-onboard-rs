use std::convert::TryFrom;
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Builder, X509NameBuilder, X509},
};
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    enhanced_types::X5Bag, ownershipvoucher::OwnershipVoucher, publickey::PublicKey, types::Guid,
};
use fdo_store::{Store, StoreDriver};
use fdo_util::servers::settings_for;

mod handlers;
mod serviceinfo;

struct OwnerServiceUD {
    // Trusted keys
    #[allow(dead_code)]
    trusted_device_keys: X5Bag,

    // Stores
    ownership_voucher_store: Box<dyn Store<fdo_store::ReadWriteOpen, Guid, OwnershipVoucher>>,
    session_store: Arc<fdo_http_wrapper::server::SessionStore>,

    // Our keys
    owner_key: PKey<Private>,

    // The new Owner2Key, randomly generated, but not stored
    owner2_key: PKey<Private>,
    owner2_pub: PublicKey,

    // ServiceInfo
    service_info_configuration: crate::serviceinfo::ServiceInfoConfiguration,
}

type OwnerServiceUDT = Arc<OwnerServiceUD>;

#[derive(Debug, Deserialize)]
struct Settings {
    // Ownership Voucher storage info
    ownership_voucher_store_driver: StoreDriver,
    ownership_voucher_store_config: Option<config::Value>,

    // Session store info
    session_store_driver: StoreDriver,
    session_store_config: Option<config::Value>,

    // Trusted keys
    trusted_device_keys_path: String,

    // Our private owner key
    owner_private_key_path: String,

    // Bind information
    bind: String,

    // Service Info
    service_info: crate::serviceinfo::ServiceInfoSettings,
}

fn load_private_key(path: &str) -> Result<PKey<Private>> {
    let contents = fs::read(path)?;
    Ok(PKey::private_key_from_der(&contents)?)
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

        #[allow(unused_must_use)]
        let (ov_res, ses_res) = tokio::join!(ov_maint, ses_maint);
        if let Err(e) = ov_res {
            log::warn!("Error during ownership voucher store maintenance: {:?}", e);
        }
        if let Err(e) = ses_res {
            log::warn!("Error during session store maintenance: {:?}", e);
        }
    }
}

/// Generate an ephemeral owner2 key: we do not support reuse or resale protocols
fn generate_owner2_keys() -> Result<(PKey<Private>, PublicKey)> {
    let owner2_key_group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("Error getting nist 256 group")?;
    let owner2_key = EcKey::generate(&owner2_key_group).context("Error generating owned2 key")?;
    let owner2_key =
        PKey::from_ec_key(owner2_key).context("ERror converting owner2 key to PKey")?;

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
    fdo_http_wrapper::init_logging();

    let settings: Settings = settings_for("owner-onboarding-server")?
        .try_into()
        .context("Error parsing configuration")?;

    // Bind information
    let bind_addr = SocketAddr::from_str(&settings.bind)
        .with_context(|| format!("Error parsing bind string '{}'", &settings.bind))?;

    // ServiceInfo settings
    let service_info_configuration =
        crate::serviceinfo::ServiceInfoConfiguration::from_settings(settings.service_info.clone())
            .context("Error preparing ServiceInfo configuration")?;

    // Trusted keys
    let trusted_device_keys = {
        let trusted_keys_path = &settings.trusted_device_keys_path;
        let contents = std::fs::read(&trusted_keys_path).with_context(|| {
            format!(
                "Error reading trusted device keys from {}",
                trusted_keys_path
            )
        })?;
        X509::stack_from_pem(&contents).context("Error parsing trusted device keys")?
    };
    let trusted_device_keys = X5Bag::with_certs(trusted_device_keys)
        .context("Error building trusted device keys X5Bag")?;

    // Our private key
    let owner_key = load_private_key(&settings.owner_private_key_path).with_context(|| {
        format!(
            "Error loading owner key from {}",
            &settings.owner_private_key_path
        )
    })?;

    // Initialize stores
    let ownership_voucher_store = settings
        .ownership_voucher_store_driver
        .initialize(settings.ownership_voucher_store_config)
        .context("Error initializing ownership voucher datastore")?;
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)
        .context("Error initializing session store")?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);

    // Generate a new Owner2
    let (owner2_key, owner2_pub) =
        generate_owner2_keys().context("Error generating new owner2 keys")?;

    // Initialize user data
    let user_data = Arc::new(OwnerServiceUD {
        // Stores
        ownership_voucher_store,
        session_store: session_store.clone(),

        // Trusted keys
        trusted_device_keys,

        // Private owner key
        owner_key,

        // Ephemeral owner2 key
        owner2_key,
        owner2_pub,

        // Service Info
        service_info_configuration,
    });

    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the owner onboarding service");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    // TO2
    let handler_to2_hello_device = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::hello_device,
    );
    let handler_to2_get_ov_next_entry = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::get_ov_next_entry,
    );
    let handler_to2_prove_device = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::prove_device,
    );
    let handler_to2_device_service_info_ready = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::device_service_info_ready,
    );
    let handler_to2_device_service_info = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::device_service_info,
    );
    let handler_to2_done = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::done,
    );

    let routes = warp::post()
        .and(
            hello
                .or(handler_ping)
                // TO2
                .or(handler_to2_hello_device)
                .or(handler_to2_get_ov_next_entry)
                .or(handler_to2_prove_device)
                .or(handler_to2_device_service_info_ready)
                .or(handler_to2_device_service_info)
                .or(handler_to2_done),
        )
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
    let _ = tokio::select!(
    _ = server => {
        log::info!("Server terminated");
    },
    _ = maintenance_runner => {
        log::info!("Maintenance runner terminated");
    });

    Ok(())
}
