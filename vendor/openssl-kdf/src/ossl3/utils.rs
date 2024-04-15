#![allow(unused)]

use libc::c_int;
use openssl::error::ErrorStack;

pub(super) fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub(super) fn cvt_cp<T>(r: *const T) -> Result<*const T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub(super) fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

macro_rules! foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident;
    )
        => {
            ::foreign_types::foreign_type! {
                $(#[$impl_attr])*
                type CType = $ctype;
                fn drop = $drop;
                $(fn clone = $clone;)*
                $(#[$owned_attr])*
                pub struct $owned;
                $(#[$borrowed_attr])*
                pub struct $borrowed;
            }

            impl $owned {
                unsafe fn from_ptr(val: *mut $ctype) -> $owned {
                    $owned(val)
                }

                unsafe fn as_ptr(&self) -> *mut $ctype {
                    self.0
                }
            }

            unsafe impl Send for $owned{}
            unsafe impl Send for $borrowed{}
            unsafe impl Sync for $owned{}
            unsafe impl Sync for $borrowed{}
        };
}
