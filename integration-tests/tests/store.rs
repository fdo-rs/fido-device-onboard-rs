mod common;
use anyhow::{Context, Result};
use fdo_data_formats::{ownershipvoucher::OwnershipVoucher, types::Guid};
use fdo_store::{
    DirectoryStorageMode, FdoMetadata, MetadataLocalKey, Store, StoreError, FDO_METADATA_EX,
};
use fdo_util::servers::configuration::manufacturing_server::ManufacturingServerSettings;
use fdo_util::servers::configuration::owner_onboarding_server::OwnerOnboardingServerSettings;
use fdo_util::servers::{settings_for, OwnershipVoucherStoreMetadataKey};
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use time;
use xattr::FileExt;

#[tokio::test]
async fn test_00_initialize() -> Result<()> {
    fdo_util::add_version!();
    let settings: ManufacturingServerSettings = settings_for("test-manufacturing")?.try_into()?;
    let _ov_store: Box<
        dyn Store<
            fdo_store::WriteOnlyOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings.ownership_voucher_store_driver.initialize()?;
    let _ov_store2: Box<
        dyn Store<
            fdo_store::WriteOnlyOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings
        .session_store_driver
        .initialize_explicit_mode(DirectoryStorageMode::MetadataFile)?;
    Ok(())
}

// based on impl MetadataValue for time::Duration, but tailored for us, and public
fn to_stored_wrapper(duration: &time::Duration) -> Vec<u8> {
    let ttl = time::OffsetDateTime::now_utc() + *duration;
    i64::to_le_bytes(ttl.unix_timestamp()).into()
}

fn compare_vectors(v1: &Vec<u8>, v2: &Vec<u8>) -> bool {
    (v1.len() == v2.len()) && v1.into_iter().zip(v2).all(|(a, b)| a.eq(b))
}

#[tokio::test]
async fn test_01_store_metadata() -> Result<()> {
    let settings: ManufacturingServerSettings = settings_for("test-manufacturing")?.try_into()?;
    let ov_store: Box<
        dyn Store<
            fdo_store::ReadWriteOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings.ownership_voucher_store_driver.initialize()?;
    // store contents
    let wait_seconds = time::Duration::new(60 as i64, 0);
    for path in std::fs::read_dir("vouchers/by-guid-pem")? {
        let path = path?.path();
        // skip metadata files, those are not OVs
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let voucher = OwnershipVoucher::from_pem(&std::fs::read(&path)?)?;
        ov_store
            .store_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Ttl,
                &wait_seconds,
            )
            .await?;
    }
    // retrieve contents, check that they're the same
    for path in std::fs::read_dir("vouchers/by-guid-pem")? {
        let path = path?.path();
        // skip .fdo-md files, those are not OVs
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let file = File::open(&path)?;
        // The proper way to get this xattr is to use to_key, but it is private
        // and we don't want to make that one public, so "store_ttl" is hardcored
        match file.get_xattr(fdo_store::format_xattr("store_ttl")) {
            Ok(Some(ttl)) => {
                assert!(compare_vectors(&to_stored_wrapper(&wait_seconds), &ttl))
            }
            Ok(None) => assert!(false),
            Err(_) => assert!(false),
        };
    }
    Ok(())
}

#[tokio::test]
async fn test_01_store_metadata_metadata_mode() -> Result<()> {
    let settings: ManufacturingServerSettings = settings_for("test-manufacturing")?.try_into()?;
    let ov_store: Box<
        dyn Store<
            fdo_store::ReadWriteOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings
        .ownership_voucher_store_driver
        .initialize_explicit_mode(DirectoryStorageMode::MetadataFile)?;
    let wait_seconds = time::Duration::new(60 as i64, 0);
    for path in std::fs::read_dir("vouchers/by-guid-pem")? {
        let path = path?.path();
        // skip .fdo-md files, those are not OVs
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let voucher = OwnershipVoucher::from_pem(&std::fs::read(&path)?)?;
        ov_store
            .store_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Ttl,
                &wait_seconds,
            )
            .await?;
    }
    for path in std::fs::read_dir("vouchers/by-guid-pem")? {
        let path = path?.path();
        // skip files that do not have .fdo-md extension
        match path.as_path().extension() {
            None => continue,
            Some(ex) => {
                if ex != FDO_METADATA_EX {
                    continue;
                }
            }
        };
        let file = File::open(&path)?;
        let metadata: FdoMetadata = serde_cbor::from_reader(&file)?;
        let ttl = metadata.map.get("store_ttl").unwrap();
        assert!(compare_vectors(&to_stored_wrapper(&wait_seconds), &ttl));
    }
    Ok(())
}

#[tokio::test]
async fn test_02_load_data_metadata_mode() -> Result<()> {
    // OVs need to be extended with the owner cert and in COSE format for this
    // test
    let settings: OwnerOnboardingServerSettings = settings_for("test-owner")?
        .try_into()
        .context("Error parsing config")?;
    let ov_store: Box<
        dyn Store<
            fdo_store::ReadWriteOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings
        .ownership_voucher_store_driver
        .initialize_explicit_mode(DirectoryStorageMode::MetadataFile)?;

    // store valid ttl metadata so that the OV is not discarded by the load_data
    // method that we are going to test (which is also a valid thing to do)
    let wait_seconds = time::Duration::new(600 as i64, 0);
    for path in std::fs::read_dir("vouchers/by-guid-cose")? {
        let path = path?.path();
        // skip metadata
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let voucher = OwnershipVoucher::from_pem_or_raw(&std::fs::read(&path)?)?;
        ov_store
            .store_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Ttl,
                &wait_seconds,
            )
            .await?;
    }

    for path in std::fs::read_dir("vouchers/by-guid-cose")? {
        let path = path?.path();
        // skip metadata files
        match path.as_path().extension() {
            Some(_) => continue,
            None => (),
        }
        // try to load the OV
        let guid = path.file_name().unwrap().to_str().unwrap();
        let ov = ov_store.load_data(&Guid::from_str(guid).unwrap()).await?;
        match ov {
            Some(ov) => assert!(ov.num_entries() == 1),
            None => (),
        };
    }
    Ok(())
}

fn load_metadata(path: &PathBuf) -> Result<FdoMetadata, StoreError> {
    let mut npath = path.to_owned();
    if path.as_path().extension().is_none() {
        npath = fdo_store::set_metadata_extension_to_path(path)?;
    }
    let file = match File::open(&npath) {
        Ok(f) => f,
        Err(e) => {
            return Err(StoreError::Unspecified(format!(
                "error on load_metadata {}",
                e
            )))
        }
    };
    let metadata: FdoMetadata = match serde_cbor::from_reader(&file) {
        Ok(data) => data,
        Err(e) => {
            return Err(StoreError::Unspecified(format!(
                "Error deserialising data: {}",
                e
            )))
        }
    };
    Ok(metadata)
}

#[tokio::test]
async fn test_03_destroy_medatada_metadata_mode() -> Result<()> {
    let settings: OwnerOnboardingServerSettings = settings_for("test-owner")?
        .try_into()
        .context("Error parsing config")?;
    let ov_store: Box<
        dyn Store<
            fdo_store::ReadWriteOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    > = settings
        .ownership_voucher_store_driver
        .initialize_explicit_mode(DirectoryStorageMode::MetadataFile)?;

    // store valid metadata
    let wait_seconds = time::Duration::new(123456, 0);
    for path in std::fs::read_dir("vouchers/by-guid-cose")? {
        let path = path?.path();
        // skip metadata
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let voucher = OwnershipVoucher::from_pem_or_raw(&std::fs::read(&path)?)?;
        ov_store
            .store_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed),
                &true,
            )
            .await?;
        ov_store
            .store_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Local(
                    OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds,
                ),
                &wait_seconds,
            )
            .await?;
    }
    // destroy the metadata, note that we are checking the removal of each key
    // separately
    for path in std::fs::read_dir("vouchers/by-guid-cose")? {
        let path = path?.path();
        // skip metadata files
        match path.as_path().extension() {
            Some(_) => continue,
            _ => (),
        };
        let voucher = OwnershipVoucher::from_pem(&std::fs::read(&path)?)?;
        ov_store
            .destroy_metadata(
                voucher.header().guid(),
                &fdo_store::MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed),
            )
            .await?;
        let fdo_metadata = load_metadata(&path)?;
        match fdo_metadata.map.get(
            &fdo_store::MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed)
                .to_key()
                .to_string(),
        ) {
            Some(_) => assert!(false),
            None => assert!(true),
        };
        match fdo_metadata.map.get(
            &fdo_store::MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds)
                .to_key()
                .to_string(),
        ) {
            Some(_) => assert!(true),
            None => assert!(false),
        };
    }

    Ok(())
}
