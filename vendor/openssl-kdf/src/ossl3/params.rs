#![allow(unused)]

use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::ptr;

use libc::*;

use super::utils::cvt_p;
use crate::KdfError;

enum Param {
    I32(*mut c_int),
    String(*mut c_char, usize),
    Vec(*mut c_void, usize),
}

impl Param {
    fn alloc_i32(val: i32) -> Result<Param, KdfError> {
        let p = unsafe {
            cvt_p(openssl_sys::CRYPTO_malloc(
                mem::size_of::<c_int>(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }? as *mut c_int;
        unsafe { *p = val };

        Ok(Param::I32(p))
    }

    fn alloc_string(val: &[u8]) -> Result<Param, KdfError> {
        let p = unsafe {
            cvt_p(openssl_sys::CRYPTO_malloc(
                val.len(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }?;
        unsafe { ptr::copy_nonoverlapping(val.as_ptr(), p as *mut u8, val.len()) };

        Ok(Param::String(p as *mut c_char, val.len()))
    }

    fn alloc_vec(val: &[u8]) -> Result<Param, KdfError> {
        let p = unsafe {
            cvt_p(openssl_sys::CRYPTO_malloc(
                val.len(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }?;
        unsafe { ptr::copy_nonoverlapping(val.as_ptr(), p as *mut u8, val.len()) };

        Ok(Param::Vec(p, val.len()))
    }
}

macro_rules! drop_param {
    ($p:ident) => {{
        openssl_sys::CRYPTO_free(
            $p as *mut c_void,
            concat!(file!(), "\0").as_ptr() as *const _,
            line!() as c_int,
        );
    }};
}

impl Drop for Param {
    fn drop(&mut self) {
        unsafe {
            match *self {
                Param::I32(p) => drop_param!(p),
                Param::String(p, _) => drop_param!(p),
                Param::Vec(p, _) => drop_param!(p),
            }
        }
    }
}

pub struct ParamsBuilder(Vec<(*const u8, Param)>);

impl ParamsBuilder {
    pub fn with_capacity(capacity: usize) -> Self {
        let params = Vec::with_capacity(capacity);
        Self(params)
    }

    pub fn build(self) -> Params {
        let len = self.0.len();

        let mut params = Params {
            fixed: self.0,
            output: Vec::with_capacity(len + 1),
        };

        // Mapping each argument held in the builder, and mapping them to a new output Vec.
        // This new output vec is to be consumed by a EVP_KDF_CTX_set_params or similar function
        // the output vec references data held in the first vec.
        // Data is allocated by the openssl allocator, so assumed in a memory stable realm.
        // It's important the data does not move from the time we create the "output" slice and the
        // moment it's read by the EVP_KDF_CTX_set_params functions.
        for (name, ref mut p) in &mut params.fixed {
            use Param::*;
            let v = unsafe {
                match p {
                    I32(v) => {
                        let pname = *name as *const c_char;
                        super::sys::OSSL_PARAM_construct_int(pname, *v)
                    }
                    Vec(buf, len) => {
                        let pname = *name as *const c_char;
                        super::sys::OSSL_PARAM_construct_octet_string(pname, *buf, *len)
                    }
                    String(buf, len) => {
                        let pname = *name as *const c_char;
                        super::sys::OSSL_PARAM_construct_utf8_string(pname, *buf, *len)
                    }
                }
            };
            params.output.push(v);
        }
        params.output.push(super::sys::OSSL_PARAM_END);
        params
    }
}

macro_rules! add_construct {
    ($func:ident, $name:ident, $ty:ty) => {
        impl ParamsBuilder {
            pub fn $func(&mut self, key: *const u8, val: $ty) -> Result<(), KdfError> {
                self.0.push((key, Param::$name(val)?));
                Ok(())
            }
        }
    };
}

add_construct!(add_i32, alloc_i32, i32);
add_construct!(add_string, alloc_string, &[u8]);
add_construct!(add_slice, alloc_vec, &[u8]);

pub struct Params {
    fixed: Vec<(*const u8, Param)>,
    output: Vec<super::sys::OSSL_PARAM>,
}

impl Params {
    pub fn len(&self) -> usize {
        self.output.len()
    }

    pub fn names(&self) -> Vec<String> {
        let mut names = Vec::new();

        for o in &self.output {
            if o.data_type != 0 {
                let cname = unsafe { CStr::from_ptr(o.key) };
                names.push(cname.to_str().expect("Invalid param name?").to_owned());
            }
        }

        names
    }

    pub fn as_mut_ptr(&mut self) -> *mut super::sys::OSSL_PARAM {
        self.output.as_mut_ptr()
    }

    pub fn as_ptr(&mut self) -> *const super::sys::OSSL_PARAM {
        self.output.as_ptr()
    }
}

const PRINTABLE_PARAMS: &[&str] = &["mode", "mac", "cipher", "digest"];

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params([")?;
        for o in &self.output {
            write!(f, "OSSL_PARAM {{")?;
            if o.data_type != 0 {
                let name = unsafe { CStr::from_ptr(o.key) };
                let name = name.to_str().unwrap();

                write!(f, "name = {:?}, ", name)?;
                write!(f, "buf = {:?}, ", o.data)?;
                write!(f, "len = {:?}", o.data_size)?;

                if PRINTABLE_PARAMS.contains(&name) {
                    let contents = unsafe { CStr::from_ptr(o.data as *const c_char) };
                    write!(f, " (value = {:?})", contents);
                }
            } else {
                write!(f, "END")?;
            }

            write!(f, "}}, ")?;
        }
        write!(f, "])")
    }
}
