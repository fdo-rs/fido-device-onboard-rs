mod common;

use std::path::Path;

use anyhow::{Context, Result};

use fdo_data_formats::ownershipvoucher::OwnershipVoucher;

fn test_single_voucher(path: &Path) -> Result<()> {
    let voucher = std::fs::read(path).context("Error reading OV")?;
    let voucher = OwnershipVoucher::from_pem_or_raw(&voucher).context("Error parsing OV")?;

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

#[test]
fn test_vouchers() -> Result<()> {
    let mut success = true;
    for path in std::fs::read_dir("vouchers/").context("Error listing vouchers")? {
        let path = path.context("Error getting voucher path")?.path();

        match test_single_voucher(&path)
            .with_context(|| format!("Error testing voucher: {}", path.display()))
        {
            Ok(_) => {}
            Err(e) => {
                println!("Error testing voucher: {:?}", e);
                success = false;
            }
        }
    }

    if success {
        Ok(())
    } else {
        Err(anyhow::anyhow!("One or more vouchers failed"))
    }
}
