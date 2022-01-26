mod common;

use std::path::Path;

use anyhow::{Context, Result};

use fdo_data_formats::{
    ownershipvoucher::OwnershipVoucher, DeserializableMany, Error, ProtocolVersion,
};

fn test_single_voucher(_path: &Path, voucher: &[u8]) -> Result<()> {
    let voucher = OwnershipVoucher::from_pem(&voucher).context("Error parsing OV")?;

    println!("Voucher: {:?}", voucher);

    // Try to iterate over the entries. This will validate everything.
    let voucheriter = voucher
        .iter_entries()
        .context("Error constructing voucher iterator")?;
    for entry in voucheriter {
        println!("Entry: {:?}", entry.context("Error parsing OV Entry")?);
    }

    Ok(())
}

fn execute_for_each_voucher<B, F>(directory: &str, init: B, mut f: F) -> Result<B>
where
    F: FnMut(B, &std::path::Path, &[u8]) -> Result<B>,
{
    let mut result = init;

    for path in std::fs::read_dir(directory).context("Error listing vouchers")? {
        let path = path.context("Error getting voucher path")?.path();

        result = f(
            result,
            &path,
            &std::fs::read(&path).context("Error reading voucher")?,
        )?;
    }

    Ok(result)
}

#[test]
fn test_vouchers() -> Result<()> {
    let success = execute_for_each_voucher("vouchers/v101/", true, |success, path, voucher| {
        Ok(success && test_single_voucher(&path, voucher).is_ok())
    })
    .context("Error running tests")?;

    if success {
        Ok(())
    } else {
        Err(anyhow::anyhow!("One or more vouchers failed"))
    }
}

#[test]
fn test_multiple_vouchers_raw() -> Result<()> {
    let mut count = 0;

    let buffer =
        execute_for_each_voucher("vouchers/v101/", Vec::new(), |mut buffer, _, voucher| {
            count += 1;

            let pemblock = pem::parse(&voucher).context("Error parsing OV PEM")?;
            buffer.extend_from_slice(&pemblock.contents);

            Ok(buffer)
        })?;

    let parsed = OwnershipVoucher::deserialize_many_from_reader(&*buffer)
        .context("Error parsing multiple vouchers")?;

    assert_eq!(count, parsed.len());

    Ok(())
}

#[test]
fn test_multiple_vouchers_pem() -> Result<()> {
    let mut count = 0;

    let buffer =
        execute_for_each_voucher("vouchers/v101/", Vec::new(), |mut buffer, _, voucher| {
            count += 1;
            let pemblock = pem::parse(&voucher).context("Error parsing OV PEM")?;
            let pemstring = pem::encode(&pemblock);
            buffer.extend_from_slice(&pemstring.as_bytes());
            Ok(buffer)
        })?;

    let parsed =
        OwnershipVoucher::many_from_pem(&*buffer).context("Error parsing multiple vouchers")?;

    assert_eq!(count, parsed.len());

    Ok(())
}

// We explicitly decided to drop support for the old format.
#[test]
fn test_voucher_v100() -> Result<()> {
    let success = execute_for_each_voucher("vouchers/v100/", true, |success, _path, voucher| {
        let voucher_result = OwnershipVoucher::from_pem(&voucher);
        Ok(success
            && matches!(
                voucher_result,
                Err(Error::UnsupportedVersion(Some(ProtocolVersion::Version1_0)))
            ))
    })
    .context("Error running tests")?;

    if success {
        Ok(())
    } else {
        Err(anyhow::anyhow!("One or more vouchers failed"))
    }
}
