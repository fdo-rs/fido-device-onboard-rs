// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::slice;

use libc::c_void;

#[cfg(cryptsetup23supported)]
use crate::Result;

macro_rules! define_handle {
    ($(#[$docs:meta])* $name:ident, $(#[$from_ptr_docs:meta])* from_ptr $(, $drop:expr)?) => {
        $(#[$docs])*
        #[cfg(cryptsetup23supported)]
        pub struct $name(*mut c_void, usize);

        #[cfg(cryptsetup23supported)]
        impl $name {
            $(#[$from_ptr_docs])*
            pub unsafe fn from_ptr(ptr: *mut c_void, size: usize) -> Self {
                $name(ptr, size)
            }
        }

        #[cfg(cryptsetup23supported)]
        impl Drop for $name {
            fn drop(&mut self) {
                self.safe_memzero();
                $(
                    #[allow(clippy::redundant_closure_call)]
                    unsafe { $drop(self) };
                )?
            }
        }
    };
}

macro_rules! memzero {
    ($name:ident) => {
        #[cfg(cryptsetup23supported)]
        impl SafeMemzero for $name {
            fn safe_memzero(&mut self) {
                mutex!(libcryptsetup_rs_sys::crypt_safe_memzero(self.0, self.1))
            }
        }
    };
}

macro_rules! as_ref {
    ($name:ident) => {
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.0.cast::<u8>(), self.1) }
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.0.cast::<u8>(), self.1) }
            }
        }
    };
}

/// A trait to be implemented for a segment of memory that can be explicitly
/// zeroed in a way that will not be optimized away by the compiler.
#[cfg(cryptsetup23supported)]
pub trait SafeMemzero {
    /// Zero the data in the buffer. To enable managed zeroing of a buffer,
    /// call this in a `Drop` implementation.
    fn safe_memzero(&mut self);
}

define_handle! {
    /// Handle for zeroing owned memory. "Owned" in this context refers to memory
    /// that has been allocated and stored in some kind of `char **` argument
    /// in the context of C FFI. This means that the memory has been allocated
    /// by standard C allocators and needs to be cleaned up by the caller.
    /// In the context of Rust, we would consider this owned by the current scope.
    ///
    /// # SECURITY WARNING
    ///
    /// Any pointer used with this *must point to memory allocated by* `libc::malloc`
    /// or any other function compatible with `libc::free`. If it has not been,
    /// you could cause memory corruption and security problems.
    SafeOwnedMemZero,
    /// Construct a safe memory handle from a pointer and a size.
    ///
    /// # Safety
    ///
    /// The pointer must point to memory allocated by `libc::malloc` or something
    /// compatible with `libc::free`. See the struct-level security warning for more
    /// information. The `size` argument also must match the length of the
    /// allocated block or memory corruption could occur.
    from_ptr,
    |self_: &mut SafeOwnedMemZero| {
        libc::free(self_.0);
    }
}
memzero!(SafeOwnedMemZero);
#[cfg(cryptsetup23supported)]
as_ref!(SafeOwnedMemZero);

define_handle! {
    /// Handle for zeroing borrowed memory. "Borrowed" in this context refers to memory
    /// that will be cleaned up by some other scope and is not required to be freed
    /// by the caller. An example of this would be a `char *` pointer to kernel memory
    /// where the caller can access the memory but is not responsible for its
    /// allocation or deallocation.
    SafeBorrowedMemZero,
    /// Construct a safe memory handle from a pointer and a size.
    ///
    /// # Safety
    ///
    /// The length must match the length of the exposed memory block
    /// or memory corruption could occur.
    from_ptr
}
memzero!(SafeBorrowedMemZero);
#[cfg(cryptsetup23supported)]
as_ref!(SafeBorrowedMemZero);

/// Handle to allocated memory from libcryptsetup
pub struct SafeMemHandle(*mut c_void, usize);

impl SafeMemHandle {
    pub(crate) unsafe fn from_ptr(ptr: *mut c_void, size: usize) -> Self {
        SafeMemHandle(ptr, size)
    }

    /// Allocate a block of memory that will be safely zeroed when deallocated
    /// by the `Drop` trait.
    #[cfg(cryptsetup23supported)]
    pub fn alloc(size: usize) -> Result<Self> {
        let ptr = ptr_to_result!(mutex!(libcryptsetup_rs_sys::crypt_safe_alloc(size)))?;
        Ok(SafeMemHandle(ptr, size))
    }
}

// libcryptsetup uses standard C heap allocation to allocate the safe memory. As a
// result, it is safe to send and access across threads.
unsafe impl Send for SafeMemHandle {}

impl Drop for SafeMemHandle {
    fn drop(&mut self) {
        mutex!(libcryptsetup_rs_sys::crypt_safe_free(self.0))
    }
}
memzero!(SafeMemHandle);
as_ref!(SafeMemHandle);

#[cfg(all(test, cryptsetup23supported, feature = "mutex"))]
mod test {
    use super::*;

    use std::io::Write;

    #[test]
    fn test_memzero() {
        let mut handle = SafeMemHandle::alloc(32).unwrap();
        handle.as_mut().write_all(&[20; 32]).unwrap();
        assert_eq!(&[20; 32], handle.as_ref());
        handle.safe_memzero();
        assert_eq!(&[0; 32], handle.as_ref());
    }

    #[test]
    fn test_memzero_borrowed() {
        let mut slice = [0u8; 32];
        let mut borrowed_handle =
            unsafe { SafeBorrowedMemZero::from_ptr(slice.as_mut_ptr().cast(), slice.len()) };
        borrowed_handle.as_mut().write_all(&[33; 32]).unwrap();
        assert_eq!(&[33; 32], borrowed_handle.as_ref());
        std::mem::drop(borrowed_handle);
        assert_eq!(&[0u8; 32], &slice);
    }
}
