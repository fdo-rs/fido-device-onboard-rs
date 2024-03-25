#[cfg(not(feature = "std"))]
extern crate alloc;

use libc::c_void;

use std::alloc::Layout;
use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::{copy_nonoverlapping, NonNull};

#[cfg(not(feature = "std"))]
use self::alloc::alloc::handle_alloc_error;
#[cfg(feature = "std")]
use std::alloc::handle_alloc_error;

#[cfg(feature = "nightly")]
use std::marker::Unsize;
#[cfg(feature = "nightly")]
use std::ops::CoerceUnsized;

//{{{ Unique --------------------------------------------------------------------------------------

/// Same as `std::ptr::Unique`, but provides a close-enough representation on stable channel.
pub struct Unique<T: ?Sized> {
    pointer: NonNull<T>,
    marker: PhantomData<T>,
}

unsafe impl<T: Send + ?Sized> Send for Unique<T> {}

unsafe impl<T: Sync + ?Sized> Sync for Unique<T> {}

impl<T: ?Sized> Unique<T> {
    /// Creates a new raw unique pointer.
    ///
    /// # Safety
    ///
    /// The `pointer`'s ownership must be transferred into the result. That is,
    /// it is no longer valid to touch `pointer` and its copies directly after
    /// calling this function.
    pub const unsafe fn new(pointer: NonNull<T>) -> Self {
        Self {
            pointer,
            marker: PhantomData,
        }
    }
}

impl<T: ?Sized> Unique<T> {
    pub fn as_non_null_ptr(&self) -> NonNull<T> {
        self.pointer
    }
}

#[cfg(feature = "nightly")]
impl<T: ?Sized + Unsize<U>, U: ?Sized> CoerceUnsized<Unique<U>> for Unique<T> {}

//}}}

//{{{ gen_malloc ----------------------------------------------------------------------------------

#[cfg(windows)]
unsafe fn malloc_aligned<T>(size: usize) -> *mut c_void {
    struct AlignmentChecker<T>(PhantomData<T>);
    impl<T> AlignmentChecker<T> {
        // Ensure in compile-time that the alignment of T is 1.
        // If the alignment is >1, the subtraction here will overflow to stop compilation.
        // (This hack is needed for targeting Rust 1.36.)
        const ENSURE_ALIGNMENT_IS_1: usize = 1 - align_of::<T>();
    }
    // The assert here should be eliminated by optimization,
    // but it is used to ensure the const evaluation actually does happen.
    assert_eq!(
        0,
        AlignmentChecker::<T>::ENSURE_ALIGNMENT_IS_1,
        "Windows malloc() only support alignment of 1"
    );

    libc::malloc(size)
}

#[cfg(all(not(windows), target_os = "android"))]
unsafe fn malloc_aligned<T>(size: usize) -> *mut c_void {
    libc::memalign(align_of::<T>(), size)
}

#[cfg(all(not(windows), not(target_os = "android")))]
unsafe fn malloc_aligned<T>(size: usize) -> *mut c_void {
    let mut result = std::ptr::null_mut();
    let align = align_of::<T>().max(size_of::<*mut ()>());
    libc::posix_memalign(&mut result, align, size);
    result
}

/// Generic malloc function.
///
/// This function allocates memory capable of storing the array `[T; count]`.
/// The memory content will not be initialized.
///
/// If `T` is zero-sized or `count == 0`, we will call `malloc(0)` which the C
/// standard permits returning NULL. In that case, we will *allocate at least 1
/// byte* to respect the `NonNull` constraint (we cannot use `NonNull::danging()`
/// because we allow the result to be passed directly to C's `free()`).
pub fn gen_malloc<T>(count: usize) -> NonNull<T> {
    let requested_size = count.checked_mul(size_of::<T>()).expect("memory overflow");

    let mut res;
    // SAFETY: allocating should be safe, duh.
    unsafe {
        res = malloc_aligned::<T>(requested_size);
        if res.is_null() && requested_size == 0 {
            res = malloc_aligned::<T>(align_of::<T>());
        }
    }
    NonNull::new(res as *mut T).unwrap_or_else(|| handle_alloc_error(Layout::new::<T>()))
}

/// Generic free function.
///
/// # Safety
///
/// The `ptr` must be obtained from `malloc()` or similar C functions.
/// The memory content will not be dropped.
pub unsafe fn gen_free<T>(ptr: NonNull<T>) {
    libc::free(ptr.as_ptr() as *mut c_void);
}

/// Generic realloc function.
///
/// Unlike C's `realloc()`, calling `gen_realloc(ptr, x, 0)` is not equivalent
/// to `gen_free(ptr)`. Rather, it will return a properly-aligned and allocated
/// pointer to satisfy the `NonNull` constraint.
///
/// # Safety
///
/// The `ptr` must be obtained from `malloc()` or similar C functions.
pub unsafe fn gen_realloc<T>(ptr: NonNull<T>, old_count: usize, new_count: usize) -> NonNull<T> {
    if size_of::<T>() == 0 {
        return ptr;
    }

    (|| {
        // ensure `requested_size > 0` to avoid `realloc()` returning a successful NULL.
        let requested_size = new_count.checked_mul(size_of::<T>())?.max(align_of::<T>());
        let mut res = libc::realloc(ptr.as_ptr() as *mut c_void, requested_size);
        if res.is_null() {
            return None;
        }

        // Most system don't provide an `aligned_realloc`.
        // If `libc::realloc()` does not give us an aligned pointer,
        // we have to perform an additional aligned allocation and memcpy over.
        if res as usize % align_of::<T>() != 0 {
            let actual_res = malloc_aligned::<T>(requested_size);
            if actual_res.is_null() {
                return None;
            }

            // no need to do checked_mul() here since it must be <= `requested_size`.
            let copy_len = old_count.min(new_count) * size_of::<T>();
            copy_nonoverlapping(res, actual_res, copy_len);
            libc::free(res);
            res = actual_res;
        }

        NonNull::new(res as *mut T)
    })()
    .unwrap_or_else(|| handle_alloc_error(Layout::new::<T>()))
}

//}}}

//{{{ Drop counter --------------------------------------------------------------------------------

#[cfg(all(test, not(windows)))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Default))]
pub(crate) struct SharedCounter {
    #[cfg(feature = "std")]
    counter: std::rc::Rc<std::cell::Cell<usize>>,

    /// A shared, mutable counter on heap.
    #[cfg(not(feature = "std"))]
    counter: NonNull<usize>,
}

#[cfg(all(test, not(windows), not(feature = "std")))]
impl Default for SharedCounter {
    fn default() -> Self {
        let counter = gen_malloc(1);
        // SAFETY: malloc() returns an uninitialized integer which is then filled in.
        unsafe {
            std::ptr::write(counter.as_ptr(), 0);
            Self { counter }
        }
    }
}

#[cfg(all(test, not(windows)))]
impl SharedCounter {
    /// Gets the counter value.
    pub(crate) fn get(&self) -> usize {
        #[cfg(feature = "std")]
        {
            self.counter.get()
        }
        // SAFETY: `self.counter` is malloc()'ed, initialized and never freed.
        #[cfg(not(feature = "std"))]
        unsafe {
            *self.counter.as_ref()
        }
    }

    /// Asserts the counter value equals to the input. Panics when different.
    pub(crate) fn assert_eq(&self, value: usize) {
        assert_eq!(self.get(), value);
    }

    /// Increases the counter by 1.
    fn inc(&self) {
        #[cfg(feature = "std")]
        {
            self.counter.set(self.counter.get() + 1);
        }
        // SAFETY: `self.counter` is malloc()'ed, initialized and never freed.
        // Since `SharedCounter` is not Sync nor Send, we are sure the
        // modification happens in the single thread, so we don't worry about
        // the interior mutation.
        #[cfg(not(feature = "std"))]
        unsafe {
            *self.counter.as_ptr() += 1;
        }
    }
}

/// A test structure to count how many times the value has been dropped.
#[cfg(all(test, not(windows)))]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct DropCounter(SharedCounter);

#[cfg(all(test, not(windows)))]
impl std::ops::Deref for DropCounter {
    type Target = SharedCounter;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(test, not(windows)))]
impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.inc();
    }
}

//}}}

//{{{ Panic-on-clone ------------------------------------------------------------------------------

/// A test structure which panics when it is cloned.
#[cfg(test)]
#[derive(Default)]
#[repr(C)] // silence the dead code warning, we don't want a ZST here to complicate things.
pub struct PanicOnClone(u8);

#[cfg(test)]
impl Clone for PanicOnClone {
    fn clone(&self) -> Self {
        panic!("panic on clone");
    }
}

//}}}
