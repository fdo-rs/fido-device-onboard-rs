#![allow(unused, non_camel_case_types)]

use libc::*;

use super::{OSSL_LIB_CTX, OSSL_PARAM};

pub enum EVP_KDF {}
pub enum EVP_KDF_CTX {}

#[link(name = "crypto")]
extern "C" {
    pub fn EVP_KDF_fetch(
        ctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        properties: *const c_char,
    ) -> *mut EVP_KDF;
    pub fn EVP_KDF_free(kdf: *mut EVP_KDF);

    pub fn EVP_KDF_CTX_new(kdf: *mut EVP_KDF) -> *mut EVP_KDF_CTX;
    pub fn EVP_KDF_CTX_free(ctx: *mut EVP_KDF_CTX);

    pub fn EVP_KDF_CTX_reset(ctx: *mut EVP_KDF_CTX);
    pub fn EVP_KDF_CTX_get_kdf_size(ctx: *mut EVP_KDF_CTX) -> size_t;
    pub fn EVP_KDF_CTX_kdf(ctx: *mut EVP_KDF_CTX) -> *const EVP_KDF;
    pub fn EVP_KDF_derive(
        ctx: *mut EVP_KDF_CTX,
        out: *mut u8,
        n: size_t,
        params: *const OSSL_PARAM,
    ) -> c_int;

    pub fn EVP_MD_get0_name(md: *const openssl_sys::EVP_MD) -> *const c_char;

    pub fn EVP_CIPHER_get0_name(cipher: *const openssl_sys::EVP_CIPHER) -> *const c_char;

    pub fn EVP_KDF_CTX_settable_params(ctx: *mut EVP_KDF_CTX) -> *const OSSL_PARAM;
    pub fn EVP_KDF_settable_ctx_params(kdf: *mut EVP_KDF) -> *const OSSL_PARAM;
}

pub const OSSL_ALG_PARAM_DIGEST: *const u8 = b"digest\0" as *const u8;
pub const OSSL_ALG_PARAM_CIPHER: *const u8 = b"cipher\0" as *const u8;
pub const OSSL_ALG_PARAM_ENGINE: *const u8 = b"engine\0" as *const u8;
pub const OSSL_ALG_PARAM_MAC: *const u8 = b"mac\0" as *const u8;
pub const OSSL_ALG_PARAM_PROPERTIES: *const u8 = b"properties\0" as *const u8;

/* KDF / PRF parameters */
pub const OSSL_KDF_PARAM_SECRET: *const u8 = b"secret\0" as *const u8;
pub const OSSL_KDF_PARAM_KEY: *const u8 = b"key\0" as *const u8;
pub const OSSL_KDF_PARAM_SALT: *const u8 = b"salt\0" as *const u8;
pub const OSSL_KDF_PARAM_PASSWORD: *const u8 = b"pass\0" as *const u8;
pub const OSSL_KDF_PARAM_DIGEST: *const u8 = OSSL_ALG_PARAM_DIGEST;
pub const OSSL_KDF_PARAM_CIPHER: *const u8 = OSSL_ALG_PARAM_CIPHER;
pub const OSSL_KDF_PARAM_MAC: *const u8 = OSSL_ALG_PARAM_MAC;
pub const OSSL_KDF_PARAM_MAC_SIZE: *const u8 = b"maclen\0" as *const u8;
pub const OSSL_KDF_PARAM_PROPERTIES: *const u8 = OSSL_ALG_PARAM_PROPERTIES;
pub const OSSL_KDF_PARAM_ITER: *const u8 = b"iter\0" as *const u8;
pub const OSSL_KDF_PARAM_MODE: *const u8 = b"mode\0" as *const u8;
pub const OSSL_KDF_PARAM_PKCS5: *const u8 = b"pkcs5\0" as *const u8;
pub const OSSL_KDF_PARAM_UKM: *const u8 = b"ukm\0" as *const u8;
pub const OSSL_KDF_PARAM_CEK_ALG: *const u8 = b"cekalg\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_N: *const u8 = b"n\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_R: *const u8 = b"r\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_P: *const u8 = b"p\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_MAXMEM: *const u8 = b"maxmem_bytes\0" as *const u8;
pub const OSSL_KDF_PARAM_INFO: *const u8 = b"info\0" as *const u8;
pub const OSSL_KDF_PARAM_SEED: *const u8 = b"seed\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_XCGHASH: *const u8 = b"xcghash\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_SESSION_ID: *const u8 = b"session_id\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_TYPE: *const u8 = b"type\0" as *const u8;
pub const OSSL_KDF_PARAM_SIZE: *const u8 = b"size\0" as *const u8;
pub const OSSL_KDF_PARAM_CONSTANT: *const u8 = b"constant\0" as *const u8;
pub const OSSL_KDF_PARAM_PKCS12_ID: *const u8 = b"id\0" as *const u8;
pub const OSSL_KDF_PARAM_KBKDF_USE_L: *const u8 = b"use-l\0" as *const u8;
pub const OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR: *const u8 = b"use-separator\0" as *const u8;
pub const OSSL_KDF_PARAM_KBKDF_R: *const u8 = b"r\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_PARTYUINFO: *const u8 = b"partyu-info\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_PARTYVINFO: *const u8 = b"partyv-info\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_SUPP_PUBINFO: *const u8 = b"supp-pubinfo\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_SUPP_PRIVINFO: *const u8 = b"supp-privinfo\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_USE_KEYBITS: *const u8 = b"use-keybits\0" as *const u8;

/* Known KDF names */
pub const OSSL_KDF_NAME_HKDF: *const u8 = b"HKDF\0" as *const u8;
pub const OSSL_KDF_NAME_PBKDF2: *const u8 = b"PBKDF2\0" as *const u8;
pub const OSSL_KDF_NAME_SCRYPT: *const u8 = b"SCRYPT\0" as *const u8;
pub const OSSL_KDF_NAME_SSHKDF: *const u8 = b"SSHKDF\0" as *const u8;
pub const OSSL_KDF_NAME_SSKDF: *const u8 = b"SSKDF\0" as *const u8;
pub const OSSL_KDF_NAME_TLS1_PRF: *const u8 = b"TLS1-PRF\0" as *const u8;
pub const OSSL_KDF_NAME_X942KDF_ASN1: *const u8 = b"X942KDF-ASN1\0" as *const u8;
pub const OSSL_KDF_NAME_X942KDF_CONCAT: *const u8 = b"X942KDF-CONCAT\0" as *const u8;
pub const OSSL_KDF_NAME_X963KDF: *const u8 = b"X963KDF\0" as *const u8;
pub const OSSL_KDF_NAME_KBKDF: *const u8 = b"KBKDF\0" as *const u8;
pub const OSSL_KDF_NAME_KRB5KDF: *const u8 = b"KRB5KDF\0" as *const u8;
