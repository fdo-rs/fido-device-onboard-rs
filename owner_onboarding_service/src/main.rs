use std::sync::Arc;

use anyhow::{Context, Result};
use aws_nitro_enclaves_cose::COSESign1;
use openssl::x509::X509;
use serde::Deserialize;
use warp::Filter;

use fdo_data_formats::{
    enhanced_types::X5Bag, ownershipvoucher::OwnershipVoucher, publickey::PublicKey, types::Guid,
};
use fdo_store::{Store, StoreDriver};

mod handlers;

struct OwnerServiceUD {
    ownership_voucher_store: Box<dyn Store<Guid, OwnershipVoucher>>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("owner_onboarding_service"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("owner_onboarding_service"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;

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

    // TODO: Initialize rest

    // Initialize user data
    let user_data = Arc::new(OwnerServiceUD {
        ownership_voucher_store,
        // TODO
    });

    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the owner onboarding service");

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
                // TO2
                .or(handler_to2_hello_device)
                .or(handler_to2_get_ov_next_entry)
                .or(handler_to2_prove_device)
                .or(handler_to2_device_service_info_ready)
                .or(handler_to2_device_service_info)
                .or(handler_to2_done),
        )
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("owner_onboarding_service"));

    println!("Listening on :8082");
    warp::serve(routes).run(([0, 0, 0, 0], 8082)).await;
    Ok(())
}
