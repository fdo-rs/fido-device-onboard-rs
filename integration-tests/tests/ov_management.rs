mod common;
use anyhow::{bail, Context, Result};
use common::{Binary, TestContext};

#[tokio::test]
async fn test_ov_management() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;
    // start server
    let owner_onboarding_server = ctx
        .start_test_server(
            Binary::OwnerOnboardingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("serviceinfo_api_server_port", &8083);
                    Ok(())
                })?)
            },
            |_| Ok(()),
        )
        .context("Error creating owner server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    //sending request
    let client = reqwest::Client::new();

    let add_ov = client
        .post(format!(
            "https://localhost:{}/management/v1/ownership_voucher", //DevSkim: ignore DS137138
            owner_onboarding_server.server_port().unwrap()
        ))
        .header("Authorization", "Bearer TestAdminToken")
        .header("X-Number-Of-Vouchers", "1")
        .header("content-type", "application/x-pem-file")
        .body("THIS IS A INVALID BODY")
        .send()
        .await?;
    let mut failed = Vec::new();
    if add_ov.status() != 400 {
        failed.push(TestCase {
            action: "Add OV",
            error: format!("expected 400 got {}", add_ov.status()),
        })
    }

    let ov_list: [&str; 1] = ["89cb17fd-95e7-4de8-a36a-686926a7f88f"];
    let delete_ov = client
        .post(format!(
            "http://localhost:{}/management/v1/ownership_voucher/delete",
            owner_onboarding_server.server_port().unwrap()
        ))
        .json(&ov_list)
        .send()
        .await?;
    if delete_ov.status() != 400 {
        failed.push(TestCase {
            action: "Delete OV",
            error: format!("expected 400 got {}", delete_ov.status()),
        })
    }

    if failed.is_empty() {
        Ok(())
    } else {
        for failed_case in failed {
            eprintln!("Failed test: {:?}", failed_case);
        }
        bail!("Some tests failed");
    }
}

#[derive(Debug)]
struct TestCase {
    #[allow(dead_code)]
    action: &'static str,
    #[allow(dead_code)]
    error: String,
}
