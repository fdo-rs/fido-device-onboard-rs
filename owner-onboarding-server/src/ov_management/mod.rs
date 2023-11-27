use crate::OwnerServiceUD;
use fdo_data_formats::{ownershipvoucher::OwnershipVoucher, types::Guid, DeserializableMany};
use openssl::pkey::{PKey, Private};
use serde::Serialize;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use std::{str::FromStr, usize};
use thiserror::Error;
use warp::{http::HeaderValue, hyper::StatusCode, Buf};
use warp::{Filter, Rejection};

pub(crate) fn ov_filter(
    session_store: Arc<OwnerServiceUD>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let store1 = session_store.clone();
    let baseurl = warp::path("management").and(warp::path("v1"));

    let add = baseurl
        .and(warp::post())
        .and(warp::path("ownership_voucher"))
        .and(warp::path::end())
        .and(warp::header::value("X-Number-Of-Vouchers"))
        .and(warp::header::value("content-type"))
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::bytes())
        .map(move |count, content_type, body| (count, content_type, body, session_store.clone()))
        .untuple_one()
        .and_then(add_ov)
        .recover(recover_err);

    let delete = baseurl
        .and(warp::post())
        .and(warp::path("ownership_voucher"))
        .and(warp::path("delete"))
        .and(warp::path::end())
        .and(warp::header::exact("content-type", "application/json"))
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(move |uuids: Vec<String>| (uuids, store1.clone()))
        .untuple_one()
        .and_then(delete_ov)
        .recover(recover_err);

    add.or(delete)
}

async fn add_ov(
    count: HeaderValue,
    content_type: HeaderValue,
    body: impl Buf,
    user_data: Arc<OwnerServiceUD>,
) -> core::result::Result<Box<dyn warp::reply::Reply>, warp::Rejection> {
    // check for ov type
    let content_type = content_type.to_str().unwrap();
    let mut reader = body.reader();
    //max limit of ov size is 1024 * 32 bytes
    let mut dst = [0; 32768];
    let _ = reader.read(&mut dst).unwrap();

    let ovs = match content_type {
        "application/x-pem-file" => OwnershipVoucher::many_from_pem(&dst[..]),
        "application/cbor" => OwnershipVoucher::deserialize_many_from_reader(&dst[..]),
        _ => {
            let message = ErrorCode::generate(ErrorCode::RequireContentTypeHeader);
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&message),
                StatusCode::BAD_REQUEST,
            )));
        }
    };

    // parse-error
    if ovs.is_err() {
        let message = ErrorCode::generate(ErrorCode::ParseError);
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&message),
            StatusCode::BAD_REQUEST,
        )));
    }

    // check-empty
    let ovs = ovs.unwrap();
    if ovs.is_empty() {
        let message = ErrorCode::generate(ErrorCode::NoOwnershipVoucherFound);
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&message),
            StatusCode::BAD_REQUEST,
        )));
    }

    // validate the voucher count
    match validate_count(count) {
        Ok(c) => match c {
            c if c > 0 => {
                if ovs.len() != c {
                    let message =
                        ErrorCode::generate(ErrorCode::InvalidNumberOfVouchers(ovs.len()));
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&message),
                        StatusCode::BAD_REQUEST,
                    )));
                }
            }
            _ => {
                let message = ErrorCode::generate(ErrorCode::VoucherCountError);
                return Ok(Box::new(warp::reply::with_status(
                    warp::reply::json(&message),
                    StatusCode::BAD_REQUEST,
                )));
            }
        },
        Err(_) => {
            let message = ErrorCode::generate(ErrorCode::VoucherCountError);
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&message),
                StatusCode::BAD_REQUEST,
            )));
        }
    }

    let mut unowned_guid = Vec::new();
    let mut owned_guid = Vec::new();
    for (i, ov) in ovs.iter().enumerate() {
        match validate_ov(ov, &user_data.owner_key) {
            Ok(state) => {
                if state {
                    owned_guid.push(ov.header().guid().to_string());
                } else {
                    unowned_guid.push(ov.header().guid().to_string());
                }
            }
            Err(e) => match e {
                ErrorCode::IncompleteVoucherDescription() => {
                    let message = ErrorCode::generate(ErrorCode::IncompleteVoucher(
                        owned_guid.len() + unowned_guid.len(),
                    ));
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&message),
                        StatusCode::BAD_REQUEST,
                    )));
                }
                ErrorCode::InvalidVoucherSignaturesDescription() => {
                    let message = ErrorCode::generate(ErrorCode::InvalidVoucherSignatures(i));
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&message),
                        StatusCode::BAD_REQUEST,
                    )));
                }
                ErrorCode::PemParseErrorDescription() => {
                    let message = ErrorCode::generate(ErrorCode::PemParseError(owned_guid.len()));
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&message),
                        StatusCode::BAD_REQUEST,
                    )));
                }
                _ => {}
            },
        }
    }

    if !unowned_guid.is_empty() {
        let message = ErrorCode::generate(ErrorCode::UnwonedVoucher(unowned_guid));
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&message),
            StatusCode::BAD_REQUEST,
        )));
    }

    for ov in ovs.iter() {
        let update_store = user_data
            .ownership_voucher_store
            .store_data(ov.clone().header().guid().to_owned(), ov.clone())
            .await
            .map_err(|e| e.to_string());

        if let Err(e) = update_store {
            let message = ErrorCode::generate(ErrorCode::StoreError(e));
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&message),
                StatusCode::INTERNAL_SERVER_ERROR,
            )));
        }
    }

    let uuid = warp::reply::json(&owned_guid);
    Ok(Box::new(warp::reply::with_status(
        uuid,
        StatusCode::CREATED,
    )))
}

async fn delete_ov(
    uuids: Vec<String>,
    user_data: Arc<OwnerServiceUD>,
) -> core::result::Result<Box<dyn warp::reply::Reply>, warp::Rejection> {
    let mut unknown_device = Vec::new();
    for uuid in &uuids {
        if Guid::from_str(uuid).is_err() {
            let message = ErrorCode::generate(ErrorCode::UuidParseError);
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&message),
                StatusCode::BAD_REQUEST,
            )));
        }
        match user_data
            .ownership_voucher_store
            .load_data(&Guid::from_str(uuid).unwrap())
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                unknown_device.push(uuid.to_string());
            }
            Err(_) => {}
        };
    }

    if !unknown_device.is_empty() {
        let message = ErrorCode::generate(ErrorCode::UnknownDevice(unknown_device));
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&message),
            StatusCode::BAD_REQUEST,
        )));
    }

    for i in uuids {
        let update_store = user_data
            .ownership_voucher_store
            .destroy_data(&Guid::from_str(&i).unwrap())
            .await;

        if let Err(e) = update_store {
            let message = ErrorCode::generate(ErrorCode::StoreError(e.to_string()));
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&message),
                StatusCode::INTERNAL_SERVER_ERROR,
            )));
        }
    }

    Ok(Box::new(warp::reply()))
}

async fn recover_err(e: Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Unhandled rejection : {:?}", e);
    Ok(Box::new(warp::reply::with_status(
        ErrorCode::MiscError.to_string(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )))
}

#[derive(Error, Debug, Serialize)]
enum ErrorCode {
    #[error("Voucher count should be positive integer")]
    VoucherCountError,
    #[error("Content-type should be application/x-pem-file or application/cbor")]
    RequireContentTypeHeader,
    #[error("Ownership voucher not found")]
    NoOwnershipVoucherFound,
    #[error("Unable to parse UUID")]
    UuidParseError,
    #[error("PEM format error")]
    ParseError,
    #[error("{0}")]
    StoreError(String),
    #[error("{0}")]
    InvalidNumberOfVouchers(usize),
    #[error("{0:?}")]
    UnwonedVoucher(Vec<String>),
    #[error("{0:?}")]
    UnknownDevice(Vec<String>),
    #[error("Voucher signature not valid")]
    InvalidVoucherSignatures(usize),
    #[error("Incomplete Voucher")]
    IncompleteVoucher(usize),
    #[error("Error parsing PEM file")]
    PemParseError(usize),
    #[error("")]
    PemParseErrorDescription(),
    #[error("")]
    IncompleteVoucherDescription(),
    #[error("")]
    InvalidVoucherSignaturesDescription(),
    #[error("Something is wrong here, please try again")]
    MiscError,
}

#[derive(Serialize)]
struct ErrorMsg<'a> {
    error_code: &'a str,
    error_details: serde_json::Value,
}

impl ErrorCode {
    fn generate(self) -> serde_json::Value {
        match self {
            ErrorCode::VoucherCountError => {
                json!({"error": &ErrorCode::VoucherCountError.to_string()})
            }
            ErrorCode::RequireContentTypeHeader => {
                json!({"error": &ErrorCode::RequireContentTypeHeader.to_string()})
            }
            ErrorCode::NoOwnershipVoucherFound => {
                json!({"error": &ErrorCode::NoOwnershipVoucherFound.to_string()})
            }
            ErrorCode::UuidParseError => json!({"error": &ErrorCode::UuidParseError.to_string()}),
            ErrorCode::StoreError(e) => json!({ "error": &e }),
            ErrorCode::ParseError => json!(ErrorMsg {
                error_code: "parse_error",
                error_details: json! ({"error": ErrorCode::ParseError.to_string()})
            }),
            ErrorCode::InvalidNumberOfVouchers(e) => json!(ErrorMsg {
                error_code: "invalid_number_of_vouchers",
                error_details: json!({ "parsed": e })
            }),
            ErrorCode::UnwonedVoucher(e) => json!(ErrorMsg {
                error_code: "unowned_voucher",
                error_details: json!({ "unowned": e })
            }),
            ErrorCode::UnknownDevice(e) => json!(ErrorMsg {
                error_code: "unknown_device",
                error_details: json!({ "unknown": e })
            }),
            ErrorCode::InvalidVoucherSignatures(idx) => json!(ErrorMsg {
                error_code: "invalid_voucher_signatures",
                error_details: json! ({"failed_at_index": idx,"description": &ErrorCode::InvalidVoucherSignatures(idx).to_string()})
            }),
            ErrorCode::IncompleteVoucher(idx) => json!(ErrorMsg {
                error_code: "incomplete_voucher",
                error_details: json! ({"parsed_correctly": idx,"description": &ErrorCode::IncompleteVoucher(idx).to_string() })
            }),
            ErrorCode::PemParseError(idx) => json!(ErrorMsg {
                error_code: "parse_error",
                error_details: json! ({"parsed_correctly": idx,"description": ErrorCode::PemParseError(idx).to_string()})
            }),
            _ => json!({}),
        }
    }
}

fn validate_ov<'a>(
    ov: &'a OwnershipVoucher,
    owner_key: &'a PKey<Private>,
) -> Result<bool, ErrorCode> {
    ov.iter_entries()
        .map_err(|_e| ErrorCode::PemParseErrorDescription())?
        .next()
        .ok_or(|| ErrorCode::ParseError)
        .map_err(|_| ErrorCode::ParseError)?
        .map_err(|_e| ErrorCode::IncompleteVoucherDescription())?
        .public_key()
        .matches_pkey(owner_key)
        .map_err(|_e| ErrorCode::InvalidVoucherSignaturesDescription())
}

fn validate_count(count: HeaderValue) -> Result<usize, ErrorCode> {
    count
        .to_str()
        .map_err(|_| ErrorCode::VoucherCountError)?
        .parse::<usize>()
        .map_err(|_| ErrorCode::VoucherCountError)
}
