use std::fs::File;

use fdo_data_formats::types::Guid;

use std::io::prelude::*;
use std::io::Read;

#[derive(Debug)]
#[allow(dead_code)]
struct HandleOVFailure(anyhow::Error);
impl warp::reject::Reject for HandleOVFailure {}

pub(crate) async fn handler_ov(
    guid: Guid,
    udt: crate::ManufacturingServiceUDT,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ov_opt = udt
        .ownership_voucher_store
        .load_data(&guid)
        .await
        .map_err(|e| warp::reject::custom(HandleOVFailure(e.into())))?;
    if ov_opt.is_none() {
        return Err(warp::reject::not_found());
    }
    let ov_pem = ov_opt
        .unwrap()
        .to_pem()
        .map_err(|e| warp::reject::custom(HandleOVFailure(e.into())))?;
    Ok(warp::reply::with_header(
        ov_pem,
        "Content-Type",
        warp::http::header::HeaderValue::from_static("application/x-pem-file"),
    ))
}

#[derive(Debug)]
#[allow(dead_code)]
struct ExportFailure(anyhow::Error);
impl warp::reject::Reject for ExportFailure {}

pub(crate) async fn handler_export(
    udt: crate::ManufacturingServiceUDT,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ovs = udt
        .ownership_voucher_store
        .load_all_data()
        .await
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    if ovs.is_empty() {
        return Err(warp::reject::not_found());
    }
    let tmp_dir = tempfile::tempdir_in("manufacturer-server-ovs")
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    for ov in ovs {
        let file_path = tmp_dir.path().join(ov.header().guid().to_string());
        let mut tmp_file =
            File::create(file_path).map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
        tmp_file
            .write_all(
                ov.to_pem()
                    .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?
                    .as_bytes(),
            )
            .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    }
    let tmp_dir_archive = tempfile::tempdir_in("manufacturer-server-ovs-archive")
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    let tar_gz = File::create(tmp_dir_archive.path().join("ovs.tar.gz"))
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    let mut tar = tar::Builder::new(tar_gz);
    tar.append_dir_all(".", tmp_dir)
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    tar.finish()
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    let mut file = File::open(tmp_dir_archive.path().join("ovs.tar.gz"))
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| warp::reject::custom(ExportFailure(e.into())))?;
    Ok(warp::reply::with_header(
        data,
        "Content-Type",
        warp::http::header::HeaderValue::from_static("application/x-tar"),
    ))
}
