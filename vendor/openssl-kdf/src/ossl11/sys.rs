pub enum KDF {}

use libc::c_int;

#[link(name = "crypto")]
extern "C" {
    pub(super) fn EVP_KDF_CTX_new_id(_type: c_int) -> *mut KDF;
    pub(super) fn EVP_KDF_CTX_free(ctx: *mut KDF);

    pub(super) fn EVP_KDF_reset(ctx: *mut KDF);
    pub(super) fn EVP_KDF_ctrl(ctx: *mut KDF, cmd: c_int, ...) -> c_int;
    pub(super) fn EVP_KDF_derive(
        ctx: *mut KDF,
        key: *mut libc::c_uchar,
        keylen: libc::size_t,
    ) -> c_int;
}
