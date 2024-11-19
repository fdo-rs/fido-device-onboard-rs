//! Trait to instruct how to properly drop and free pointers.

use std::ptr::{drop_in_place, NonNull};

use crate::internal::gen_free;

/// Implemented for pointers which can be freed.
pub trait Free {
    /// Drops the content pointed by this pointer and frees it.
    ///
    /// # Safety
    ///
    /// The `ptr` must be allocated through `malloc()`.
    ///
    /// Do not call this method if the pointer has been freed. Users of this trait should maintain a
    /// flag to track if the pointer has been freed or not (the Rust compiler will automatically do
    /// this with a `Drop` type).
    unsafe fn free(ptr: NonNull<Self>);
}

/// Drops the content of `*ptr`, then frees the `ptr` itself.
unsafe fn free_ptr_ref<T>(ptr: NonNull<T>) {
    drop_in_place(ptr.as_ptr());
    gen_free(ptr);
}

impl<T> Free for T {
    #[cfg(feature = "nightly")]
    default unsafe fn free(ptr_ref: NonNull<Self>) {
        free_ptr_ref(ptr_ref);
    }

    #[cfg(not(feature = "nightly"))]
    unsafe fn free(ptr_ref: NonNull<Self>) {
        free_ptr_ref(ptr_ref);
    }
}

impl<T> Free for [T] {
    unsafe fn free(fat_ptr: NonNull<Self>) {
        let fat_ptr = fat_ptr.as_ptr();
        drop_in_place(fat_ptr);
        gen_free(NonNull::new_unchecked(fat_ptr as *mut T));
    }
}

impl Free for str {
    unsafe fn free(fat_ptr: NonNull<Self>) {
        Free::free(NonNull::new_unchecked(fat_ptr.as_ptr() as *mut [u8]));
    }
}
