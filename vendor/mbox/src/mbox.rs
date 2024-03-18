//! `malloc`-based Box.

#[cfg(feature = "stable_deref_trait")]
use stable_deref_trait::StableDeref;

use std::cmp::Ordering;
use std::convert::{AsMut, AsRef};
use std::fmt::{Debug, Display, Formatter, Pointer, Result as FormatResult};
use std::hash::{Hash, Hasher};
use std::iter::{DoubleEndedIterator, FromIterator, IntoIterator};
use std::marker::Unpin;
use std::mem::{forget, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr::{copy_nonoverlapping, drop_in_place, read, write};
use std::slice::{Iter, IterMut};
use std::str::{from_utf8, Utf8Error};
use std::{
    borrow::{Borrow, BorrowMut},
    ptr::NonNull,
};

use crate::internal::{gen_free, gen_malloc, gen_realloc, Unique};

#[cfg(all(test, not(windows)))]
use crate::internal::DropCounter;
#[cfg(test)]
use crate::internal::PanicOnClone;
#[cfg(test)]
use std::iter::{once, repeat};
#[cfg(all(test, not(windows)))]
use std::mem::size_of;

#[cfg(feature = "nightly")]
use std::marker::Unsize;
#[cfg(feature = "nightly")]
use std::ops::CoerceUnsized;

use crate::free::Free;

//{{{ Basic structure -----------------------------------------------------------------------------

/// A malloc-backed box. This structure allows Rust to exchange objects with C without cloning.
pub struct MBox<T: ?Sized + Free>(Unique<T>);

impl<T: ?Sized + Free> MBox<T> {
    /// Constructs a new malloc-backed box from a pointer allocated by `malloc`.
    ///
    /// # Safety
    ///
    /// The `ptr` must be allocated via `malloc()`, `calloc()` or similar C functions that is
    /// expected to be deallocated using `free()`. It must be aligned and not null. The content of the pointer
    /// must be already initialized. The pointer's ownership is passed into the box, and thus should
    /// not be used after this function returns.
    ///
    /// Note that even when `T` is zero-sized, the input `ptr` is *still* expected to be released using
    /// `free()`. Therefore, you must not use a conceived dangling pointer such as `NonNull::dangling()`
    /// here. Consider using `malloc(1)` in case of ZSTs.
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self::from_non_null_raw(NonNull::new_unchecked(ptr))
    }

    /// Constructs a new malloc-backed box from a non-null pointer allocated by `malloc`.
    ///
    /// # Safety
    ///
    /// The `ptr` must be allocated via `malloc()`, `calloc()` or similar C functions that is
    /// expected to be deallocated using `free()`. The content of the pointer must be already
    /// initialized. The pointer's ownership is passed into the box, and thus should not be used
    /// after this function returns.
    ///
    /// Note that even when `T` is zero-sized, the input `ptr` is *still* expected to be released using
    /// `free()`. Therefore, you must not use a conceived dangling pointer such as `NonNull::dangling()`
    /// here. Consider using `malloc(1)` in case of ZSTs.
    pub unsafe fn from_non_null_raw(ptr: NonNull<T>) -> Self {
        Self(Unique::new(ptr))
    }

    /// Obtains the pointer owned by the box.
    pub fn as_ptr(boxed: &Self) -> *const T {
        boxed.0.as_non_null_ptr().as_ptr()
    }

    /// Obtains the mutable pointer owned by the box.
    pub fn as_mut_ptr(boxed: &mut Self) -> *mut T {
        boxed.0.as_non_null_ptr().as_ptr()
    }

    /// Consumes the box and returns the original pointer.
    ///
    /// The caller is responsible for `free`ing the pointer after this.
    pub fn into_raw(boxed: Self) -> *mut T {
        Self::into_non_null_raw(boxed).as_ptr()
    }

    /// Consumes the box and returns the original non-null pointer.
    ///
    /// The caller is responsible for `free`ing the pointer after this.
    pub fn into_non_null_raw(boxed: Self) -> NonNull<T> {
        let ptr = boxed.0.as_non_null_ptr();
        forget(boxed);
        ptr
    }
}

impl<T: ?Sized + Free> Drop for MBox<T> {
    fn drop(&mut self) {
        // SAFETY: the pointer is assumed to be obtained from `malloc()`.
        unsafe { T::free(self.0.as_non_null_ptr()) };
    }
}

impl<T: ?Sized + Free> Deref for MBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*Self::as_ptr(self) }
    }
}

#[cfg(feature = "stable_deref_trait")]
unsafe impl<T: ?Sized + Free> StableDeref for MBox<T> {}

impl<T: ?Sized + Free> Unpin for MBox<T> {}

impl<T: ?Sized + Free> DerefMut for MBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *Self::as_mut_ptr(self) }
    }
}

impl<T: ?Sized + Free> AsRef<T> for MBox<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T: ?Sized + Free> AsMut<T> for MBox<T> {
    fn as_mut(&mut self) -> &mut T {
        self
    }
}

impl<T: ?Sized + Free> Borrow<T> for MBox<T> {
    fn borrow(&self) -> &T {
        self
    }
}

impl<T: ?Sized + Free> BorrowMut<T> for MBox<T> {
    fn borrow_mut(&mut self) -> &mut T {
        self
    }
}

#[cfg(feature = "nightly")]
impl<T: ?Sized + Free + Unsize<U>, U: ?Sized + Free> CoerceUnsized<MBox<U>> for MBox<T> {}

impl<T: ?Sized + Free> Pointer for MBox<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FormatResult {
        Pointer::fmt(&Self::as_ptr(self), formatter)
    }
}

impl<T: ?Sized + Free + Debug> Debug for MBox<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FormatResult {
        self.deref().fmt(formatter)
    }
}

impl<T: ?Sized + Free + Display> Display for MBox<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FormatResult {
        self.deref().fmt(formatter)
    }
}

impl<T: ?Sized + Free + Hash> Hash for MBox<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}

impl<U: ?Sized + Free, T: ?Sized + Free + PartialEq<U>> PartialEq<MBox<U>> for MBox<T> {
    fn eq(&self, other: &MBox<U>) -> bool {
        self.deref().eq(other.deref())
    }
}

impl<T: ?Sized + Free + Eq> Eq for MBox<T> {}

impl<U: ?Sized + Free, T: ?Sized + Free + PartialOrd<U>> PartialOrd<MBox<U>> for MBox<T> {
    fn partial_cmp(&self, other: &MBox<U>) -> Option<Ordering> {
        self.deref().partial_cmp(other.deref())
    }
}

impl<T: ?Sized + Free + Ord> Ord for MBox<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}

//}}}

//{{{ Single object -------------------------------------------------------------------------------

impl<T> MBox<T> {
    /// Constructs a new malloc-backed box, and move an initialized value into it.
    pub fn new(value: T) -> Self {
        let storage = gen_malloc(1);
        // SAFETY: the `storage` is uninitialized and enough to store T.
        // this pointer is obtained via `malloc` and thus good for `from_raw`.
        unsafe {
            write(storage.as_ptr(), value);
            Self::from_non_null_raw(storage)
        }
    }

    /// Constructs a new malloc-backed box with uninitialized content.
    pub fn new_uninit() -> MBox<MaybeUninit<T>> {
        let storage = gen_malloc(1);
        // SAFETY: The storage is allowed to be uninitialized.
        unsafe { MBox::from_non_null_raw(storage) }
    }

    /// Constructs a new `Pin<MBox<T>>`. If `T` does not implement `Unpin`, then `value` will be
    /// pinned in memory and cannot be moved.
    pub fn pin(value: T) -> Pin<Self> {
        Self::into_pin(Self::new(value))
    }

    /// Converts an `MBox<T>` into a single-item `MBox<[T]>`.
    ///
    /// This conversion does not allocate on the heap and happens in place.
    pub fn into_boxed_slice(boxed: Self) -> MBox<[T]> {
        // SAFETY: free() only cares about the allocated size, and `T` and
        // `[T; 1]` are equivalent in terms of drop() and free().
        unsafe { MBox::from_raw_parts(Self::into_raw(boxed), 1) }
    }

    /// Consumes the `MBox`, returning the wrapped value.
    pub fn into_inner(boxed: Self) -> T {
        let mut dst = MaybeUninit::uninit();
        let src = Self::into_non_null_raw(boxed);
        // SAFETY: after calling `into_raw` above, we have the entire ownership of the malloc'ed
        // pointer `src`. The content is moved into the destination. After that, we can free `src`
        // without touching the content. So there is a single copy of the content fully initialized
        // into `dst` which is safe to assume_init.
        unsafe {
            copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), 1);
            gen_free(src);
            dst.assume_init()
        }
    }

    /// Converts an `MBox<T>` into a `Pin<MBox<T>>`.
    ///
    /// This conversion does not allocate on the heap and happens in place.
    pub fn into_pin(boxed: Self) -> Pin<Self> {
        // SAFETY: Same reason as why `Box::into_pin` is safe.
        unsafe { Pin::new_unchecked(boxed) }
    }

    /// Consumes and leaks the `MBox`, returning a mutable reference, `&'a mut T`.
    pub fn leak<'a>(boxed: Self) -> &'a mut T
    where
        T: 'a,
    {
        // SAFETY: into_raw takes the ownership of the box, which is then immediately leaked. Thus,
        // no one is able to call `gen_free` on this pointer and thus safe to be used in the rest of
        // its lifetime.
        unsafe { &mut *Self::into_non_null_raw(boxed).as_ptr() }
    }
}

impl<T> MBox<MaybeUninit<T>> {
    /// Converts into an initialized box.
    ///
    /// # Safety
    ///
    /// The caller should guarantee `*self` is indeed initialized.
    pub unsafe fn assume_init(self) -> MBox<T> {
        MBox::from_non_null_raw(Self::into_non_null_raw(self).cast())
    }
}

impl<T> From<T> for MBox<T> {
    fn from(value: T) -> MBox<T> {
        MBox::new(value)
    }
}

impl<T: Clone> Clone for MBox<T> {
    fn clone(&self) -> MBox<T> {
        Self::new(self.deref().clone())
    }

    fn clone_from(&mut self, source: &Self) {
        self.deref_mut().clone_from(source);
    }
}

impl<T: Default> Default for MBox<T> {
    fn default() -> MBox<T> {
        MBox::new(T::default())
    }
}

#[cfg(not(windows))]
#[test]
fn test_single_object() {
    let counter = DropCounter::default();
    {
        let mbox = MBox::new(counter.clone());
        counter.assert_eq(0);
        drop(mbox);
    }
    counter.assert_eq(1);
}

#[test]
fn test_into_raw() {
    let mbox = MBox::new(66u8);
    let raw = MBox::into_raw(mbox);
    unsafe {
        assert_eq!(*raw, 66u8);
        gen_free(NonNull::new(raw).unwrap());
    }
}

#[cfg(not(windows))]
#[test]
fn test_clone() {
    let counter = DropCounter::default();
    {
        let first_mbox = MBox::new(counter.clone());
        {
            let second_mbox = first_mbox.clone();
            counter.assert_eq(0);
            drop(second_mbox);
        }
        counter.assert_eq(1);
    }
    counter.assert_eq(2);
}

#[cfg(not(windows))]
#[test]
fn test_clone_from() {
    let counter = DropCounter::default();
    {
        let first_mbox = MBox::new(counter.clone());
        {
            let mut second_mbox = MBox::new(counter.clone());
            counter.assert_eq(0);
            second_mbox.clone_from(&first_mbox);
            counter.assert_eq(1);
        }
        counter.assert_eq(2);
    }
    counter.assert_eq(3);
}

#[cfg(not(windows))]
#[test]
fn test_no_drop_flag() {
    fn do_test_for_drop_flag(branch: bool, expected: usize) {
        let counter = DropCounter::default();
        let inner_counter = counter.deref().clone();
        {
            let mbox;
            if branch {
                mbox = MBox::new(counter.clone());
                let _ = &mbox;
            }
            inner_counter.assert_eq(0);
        }
        inner_counter.assert_eq(expected);
    }

    do_test_for_drop_flag(true, 1);
    do_test_for_drop_flag(false, 0);

    assert_eq!(
        size_of::<MBox<DropCounter>>(),
        size_of::<*mut DropCounter>()
    );
}

#[cfg(feature = "std")]
#[test]
fn test_format() {
    let a = MBox::new(3u8);
    assert_eq!(format!("{:p}", a), format!("{:p}", MBox::as_ptr(&a)));
    assert_eq!(format!("{}", a), "3");
    assert_eq!(format!("{:?}", a), "3");
}

#[test]
fn test_standard_traits() {
    let mut a = MBox::new(0u8);
    assert_eq!(*a, 0);
    *a = 3;
    assert_eq!(*a, 3);
    assert_eq!(*a.as_ref(), 3);
    assert_eq!(*a.as_mut(), 3);
    assert_eq!(*(a.borrow() as &u8), 3);
    assert_eq!(*(a.borrow_mut() as &mut u8), 3);
    assert!(a == MBox::new(3u8));
    assert!(a != MBox::new(0u8));
    assert!(a < MBox::new(4u8));
    assert!(a > MBox::new(2u8));
    assert!(a <= MBox::new(4u8));
    assert!(a >= MBox::new(2u8));
    assert_eq!(a.cmp(&MBox::new(7u8)), Ordering::Less);
    assert_eq!(MBox::<u8>::default(), MBox::new(0u8));
}

#[test]
fn test_zero_sized_type() {
    let a = MBox::new(());
    assert!(!MBox::as_ptr(&a).is_null());
}

#[cfg(not(windows))]
#[test]
fn test_non_zero() {
    let b = 0u64;
    assert!(!Some(MBox::new(0u64)).is_none());
    assert!(!Some(MBox::new(())).is_none());
    assert!(!Some(MBox::new(&b)).is_none());

    assert_eq!(size_of::<Option<MBox<u64>>>(), size_of::<MBox<u64>>());
    assert_eq!(size_of::<Option<MBox<()>>>(), size_of::<MBox<()>>());
    assert_eq!(
        size_of::<Option<MBox<&'static u64>>>(),
        size_of::<MBox<&'static u64>>()
    );
}

#[cfg(not(windows))]
#[test]
fn test_aligned() {
    use std::mem::align_of;

    let b = MBox::new(1u16);
    assert_eq!(MBox::as_ptr(&b) as usize % align_of::<u16>(), 0);

    let b = MBox::new(1u32);
    assert_eq!(MBox::as_ptr(&b) as usize % align_of::<u32>(), 0);

    let b = MBox::new(1u64);
    assert_eq!(MBox::as_ptr(&b) as usize % align_of::<u64>(), 0);

    #[repr(C, align(4096))]
    struct A(u8);

    let b = MBox::new(A(2));
    assert_eq!(MBox::as_ptr(&b) as usize % 4096, 0);
}

//}}}

//{{{ Slice helpers -------------------------------------------------------------------------------

mod slice_helper {
    use super::*;

    /// A `Vec`-like structure backed by `malloc()`.
    pub struct MSliceBuilder<T> {
        ptr: NonNull<T>,
        cap: usize,
        len: usize,
    }

    impl<T> MSliceBuilder<T> {
        /// Creates a new slice builder with an initial capacity.
        pub fn with_capacity(cap: usize) -> MSliceBuilder<T> {
            MSliceBuilder {
                ptr: gen_malloc(cap),
                cap,
                len: 0,
            }
        }

        pub fn push(&mut self, obj: T) {
            if self.len >= self.cap {
                let new_cap = (self.cap * 2).max(1);
                // SAFETY:
                //  - ptr is initialized from gen_malloc() so it can be placed into gen_realloc()
                unsafe {
                    self.ptr = gen_realloc(self.ptr, self.cap, new_cap);
                }
                self.cap = new_cap;
            }

            // SAFETY:
            //  - we guarantee that `ptr `points to an array of nonzero length `cap`, and
            //    the `if` condition ensures the invariant `self.len < cap`, so
            //    `ptr.add(self.len)` is always a valid (but uninitialized) object.
            //  - since `ptr[self.len]` is not yet initialized, we can `write()` into it safely.
            unsafe {
                write(self.ptr.as_ptr().add(self.len), obj);
            }
            self.len += 1;
        }

        pub fn into_mboxed_slice(self) -> MBox<[T]> {
            // SAFETY: `self.ptr` has been allocated by malloc(), and its length is self.cap
            // (>= self.len).
            let slice = unsafe { MBox::from_raw_parts(self.ptr.as_ptr(), self.len) };
            forget(self);
            slice
        }
    }

    impl<T> MSliceBuilder<MaybeUninit<T>> {
        /// Sets the length of the builder to the same as the capacity. The elements in the
        /// uninitialized tail remains uninitialized.
        pub fn set_len_to_cap(&mut self) {
            self.len = self.cap;
        }
    }

    impl<T> Drop for MSliceBuilder<T> {
        fn drop(&mut self) {
            // SAFETY: `ptr` has been allocated by `gen_malloc()`.
            unsafe {
                gen_free(self.ptr);
            }
        }
    }

    #[repr(C)]
    struct SliceParts<T> {
        ptr: *mut T,
        len: usize,
    }

    impl<T> Clone for SliceParts<T> {
        fn clone(&self) -> Self {
            Self {
                ptr: self.ptr,
                len: self.len,
            }
        }
    }
    impl<T> Copy for SliceParts<T> {}

    #[repr(C)]
    union SliceTransformer<T> {
        fat_ptr: *mut [T],
        parts: SliceParts<T>,
    }

    // TODO: maybe upgrade Rust to 1.42 to get rid of this function.
    pub fn slice_from_raw_parts_mut<T>(ptr: *mut T, len: usize) -> *mut [T] {
        // SAFETY: just the same code of the function from std.
        unsafe {
            SliceTransformer {
                parts: SliceParts { ptr, len },
            }
            .fat_ptr
        }
    }

    pub fn slice_into_raw_parts_mut<T>(fat_ptr: *mut [T]) -> (*mut T, usize) {
        let parts = unsafe { SliceTransformer { fat_ptr }.parts };
        (parts.ptr, parts.len)
    }
}

use self::slice_helper::{slice_from_raw_parts_mut, slice_into_raw_parts_mut, MSliceBuilder};

/// The iterator returned from `MBox<[T]>::into_iter()`.
pub struct MSliceIntoIter<T> {
    ptr: NonNull<T>,
    begin: usize,
    end: usize,
}

impl<T> Iterator for MSliceIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.begin == self.end {
            None
        } else {
            unsafe {
                let ptr = self.ptr.as_ptr().add(self.begin);
                self.begin += 1;
                Some(read(ptr))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.end - self.begin;
        (len, Some(len))
    }
}

impl<T> DoubleEndedIterator for MSliceIntoIter<T> {
    fn next_back(&mut self) -> Option<T> {
        if self.begin == self.end {
            None
        } else {
            unsafe {
                self.end -= 1;
                let ptr = self.ptr.as_ptr().add(self.end);
                Some(read(ptr))
            }
        }
    }
}

unsafe impl<T: Send> Send for MSliceIntoIter<T> {}
unsafe impl<T: Sync> Sync for MSliceIntoIter<T> {}

impl<T> ExactSizeIterator for MSliceIntoIter<T> {}

impl<T> Drop for MSliceIntoIter<T> {
    fn drop(&mut self) {
        unsafe {
            let base = self.ptr.as_ptr().add(self.begin);
            let len = self.end - self.begin;
            let slice = slice_from_raw_parts_mut(base, len);
            drop_in_place(slice);
            gen_free(self.ptr);
        }
    }
}

//}}}

//{{{ Slice ---------------------------------------------------------------------------------------

impl<T> MBox<[T]> {
    /// Constructs a new malloc-backed slice from the pointer and the length (number of items).
    ///
    /// # Safety
    ///
    /// `ptr` must be allocated via `malloc()` or similar C functions. It must be aligned and not null.
    ///
    /// The `malloc`ed size of the pointer must be at least `len * size_of::<T>()`. The content
    /// must already been initialized.
    pub unsafe fn from_raw_parts(ptr: *mut T, len: usize) -> Self {
        Self::from_raw(slice_from_raw_parts_mut(ptr, len))
    }

    /// Constructs a new boxed slice with uninitialized contents.
    pub fn new_uninit_slice(len: usize) -> MBox<[MaybeUninit<T>]> {
        let mut builder = MSliceBuilder::with_capacity(len);
        builder.set_len_to_cap();
        builder.into_mboxed_slice()
    }

    /// Decomposes the boxed slice into a pointer to the first element and the slice length.
    pub fn into_raw_parts(mut self) -> (*mut T, usize) {
        let (ptr, len) = slice_into_raw_parts_mut(Self::as_mut_ptr(&mut self));
        forget(self);
        (ptr, len)
    }
}

impl<T> MBox<[MaybeUninit<T>]> {
    /// Converts into an initialized boxed slice.
    ///
    /// # Safety
    ///
    /// The caller should guarantee `*self` is indeed initialized.
    pub unsafe fn assume_init(self) -> MBox<[T]> {
        MBox::from_raw(Self::into_raw(self) as *mut [T])
    }
}

impl<T> Default for MBox<[T]> {
    fn default() -> Self {
        unsafe { Self::from_raw_parts(gen_malloc(0).as_ptr(), 0) }
    }
}

impl<T: Clone> Clone for MBox<[T]> {
    fn clone(&self) -> Self {
        Self::from_slice(self)
    }
}

impl<T: Clone> MBox<[T]> {
    /// Creates a new `malloc`-boxed slice by cloning the content of an existing slice.
    pub fn from_slice(slice: &[T]) -> MBox<[T]> {
        let mut builder = MSliceBuilder::with_capacity(slice.len());
        for item in slice {
            builder.push(item.clone());
        }
        builder.into_mboxed_slice()
    }
}

impl<T> FromIterator<T> for MBox<[T]> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let (lower_size, upper_size) = iter.size_hint();
        let initial_capacity = upper_size.unwrap_or(lower_size).max(1);
        let mut builder = MSliceBuilder::with_capacity(initial_capacity);
        for item in iter {
            builder.push(item);
        }
        builder.into_mboxed_slice()
    }
}

impl<T> IntoIterator for MBox<[T]> {
    type Item = T;
    type IntoIter = MSliceIntoIter<T>;
    fn into_iter(self) -> MSliceIntoIter<T> {
        let (ptr, len) = self.into_raw_parts();
        MSliceIntoIter {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            begin: 0,
            end: len,
        }
    }
}

impl<'a, T> IntoIterator for &'a MBox<[T]> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;
    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut MBox<[T]> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;
    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

#[cfg(not(windows))]
#[test]
fn test_slice() {
    unsafe {
        let slice_content = gen_malloc::<u64>(5).as_ptr();
        *slice_content.offset(0) = 16458340076686561191;
        *slice_content.offset(1) = 15635007859502065083;
        *slice_content.offset(2) = 4845947824042606450;
        *slice_content.offset(3) = 8907026173756975745;
        *slice_content.offset(4) = 7378932587879886134;
        let mbox = MBox::from_raw_parts(slice_content, 5);
        assert_eq!(
            &mbox as &[u64],
            &[
                16458340076686561191,
                15635007859502065083,
                4845947824042606450,
                8907026173756975745,
                7378932587879886134
            ]
        );
    }
}

#[cfg(not(windows))]
#[test]
fn test_slice_with_drops() {
    let counter = DropCounter::default();
    unsafe {
        let slice_content = gen_malloc::<DropCounter>(3).as_ptr();
        {
            write(slice_content.offset(0), counter.clone());
            write(slice_content.offset(1), counter.clone());
            write(slice_content.offset(2), counter.clone());
        }
        counter.assert_eq(0);
        let mbox = MBox::from_raw_parts(slice_content, 3);
        mbox[0].assert_eq(0);
        mbox[1].assert_eq(0);
        mbox[2].assert_eq(0);
        assert_eq!(mbox.len(), 3);
    }
    counter.assert_eq(3);
}

#[cfg(feature = "nightly")]
#[test]
fn test_coerce_unsized() {
    let counter = DropCounter::default();
    {
        let pre_box = MBox::new([counter.clone(), counter.clone()]);
        counter.assert_eq(0);
        pre_box[0].assert_eq(0);
        pre_box[1].assert_eq(0);
        assert_eq!(pre_box.len(), 2);

        let post_box: MBox<[DropCounter]> = pre_box;
        counter.assert_eq(0);
        post_box[0].assert_eq(0);
        post_box[1].assert_eq(0);
        assert_eq!(post_box.len(), 2);
    }
    counter.assert_eq(2);
}

#[cfg(not(windows))]
#[test]
#[allow(useless_ptr_null_checks)]
fn test_empty_slice() {
    let mbox = MBox::<[DropCounter]>::default();
    let sl: &[DropCounter] = &mbox;
    assert_eq!(sl.len(), 0);
    assert!(!sl.as_ptr().is_null());
}

#[cfg(all(feature = "nightly", not(windows)))]
#[test]
#[allow(useless_ptr_null_checks)]
fn test_coerce_from_empty_slice() {
    let pre_box = MBox::<[DropCounter; 0]>::new([]);
    assert_eq!(pre_box.len(), 0);
    assert!(!pre_box.as_ptr().is_null());

    let post_box: MBox<[DropCounter]> = pre_box;
    let sl: &[DropCounter] = &post_box;
    assert_eq!(sl.len(), 0);
    assert!(!sl.as_ptr().is_null());
}

#[cfg(not(windows))]
#[test]
fn test_clone_slice() {
    let counter = DropCounter::default();
    unsafe {
        let slice_content = gen_malloc::<DropCounter>(3).as_ptr();
        {
            write(slice_content.offset(0), counter.clone());
            write(slice_content.offset(1), counter.clone());
            write(slice_content.offset(2), counter.clone());
        }
        let mbox = MBox::from_raw_parts(slice_content, 3);
        assert_eq!(mbox.len(), 3);

        {
            let cloned_mbox = mbox.clone();
            counter.assert_eq(0);
            assert_eq!(cloned_mbox.len(), 3);
            cloned_mbox[0].assert_eq(0);
            cloned_mbox[1].assert_eq(0);
            cloned_mbox[2].assert_eq(0);
        }

        counter.assert_eq(3);
        mbox[0].assert_eq(3);
        mbox[1].assert_eq(3);
        mbox[2].assert_eq(3);
    }

    counter.assert_eq(6);
}

#[cfg(not(windows))]
#[test]
fn test_from_iterator() {
    let counter = DropCounter::default();
    {
        let slice = repeat(counter.clone()).take(18).collect::<MBox<[_]>>();
        counter.assert_eq(1);
        assert_eq!(slice.len(), 18);
        for c in &slice {
            c.assert_eq(1);
        }
    }
    counter.assert_eq(19);
}

#[test]
fn test_from_iterator_with_no_size_hint() {
    struct RedactSizeHint<I>(I);

    impl<I: Iterator> Iterator for RedactSizeHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    let it = RedactSizeHint(b"1234567890".iter().copied());
    assert_eq!(it.size_hint(), (0, None));
    let slice = it.collect::<MBox<[u8]>>();
    assert_eq!(&*slice, b"1234567890");
}

#[cfg(not(windows))]
#[test]
fn test_into_iterator() {
    let counter = DropCounter::default();
    {
        let slice = repeat(counter.clone()).take(18).collect::<MBox<[_]>>();
        counter.assert_eq(1);
        assert_eq!(slice.len(), 18);
        for (c, i) in slice.into_iter().zip(1..) {
            c.assert_eq(i);
        }
    }
    counter.assert_eq(19);
}

#[cfg(feature = "std")]
#[test]
fn test_iter_properties() {
    let slice = vec![1i8, 4, 9, 16, 25].into_iter().collect::<MBox<[_]>>();
    let mut iter = slice.into_iter();
    assert_eq!(iter.size_hint(), (5, Some(5)));
    assert_eq!(iter.len(), 5);
    assert_eq!(iter.next(), Some(1));
    assert_eq!(iter.next_back(), Some(25));
    assert_eq!(iter.size_hint(), (3, Some(3)));
    assert_eq!(iter.len(), 3);
    assert_eq!(iter.collect::<Vec<_>>(), vec![4, 9, 16]);
}

#[cfg(not(windows))]
#[test]
fn test_iter_drop() {
    let counter = DropCounter::default();
    {
        let slice = repeat(counter.clone()).take(18).collect::<MBox<[_]>>();
        counter.assert_eq(1);
        assert_eq!(slice.len(), 18);

        let mut iter = slice.into_iter();
        counter.assert_eq(1);
        {
            iter.next().unwrap().assert_eq(1)
        };
        {
            iter.next().unwrap().assert_eq(2)
        };
        {
            iter.next_back().unwrap().assert_eq(3)
        };
        counter.assert_eq(4);
    }
    counter.assert_eq(19);
}

#[test]
fn test_zst_slice() {
    let slice = repeat(()).take(7).collect::<MBox<[_]>>();
    let _ = slice.clone();
    slice.into_iter();
}

#[test]
#[should_panic(expected = "panic on clone")]
fn test_panic_during_clone() {
    let mbox = MBox::<PanicOnClone>::default();
    let _ = mbox.clone();
}

#[test]
#[should_panic(expected = "panic on clone")]
fn test_panic_during_clone_from() {
    let mut mbox = MBox::<PanicOnClone>::default();
    let other = MBox::default();
    mbox.clone_from(&other);
}

//}}}

//{{{ UTF-8 String --------------------------------------------------------------------------------

impl MBox<str> {
    /// Constructs a new malloc-backed string from the pointer and the length (number of UTF-8 code
    /// units).
    ///
    /// # Safety
    ///
    /// The `malloc`ed size of the pointer must be at least `len`. The content must already been
    /// initialized and be valid UTF-8.
    pub unsafe fn from_raw_utf8_parts_unchecked(value: *mut u8, len: usize) -> MBox<str> {
        Self::from_utf8_unchecked(MBox::from_raw_parts(value, len))
    }

    /// Constructs a new malloc-backed string from the pointer and the length (number of UTF-8 code
    /// units). If the content does not contain valid UTF-8, this method returns an `Err`.
    ///
    /// # Safety
    ///
    /// The `malloc`ed size of the pointer must be at least `len`.
    /// The content must already been initialized.
    pub unsafe fn from_raw_utf8_parts(value: *mut u8, len: usize) -> Result<MBox<str>, Utf8Error> {
        Self::from_utf8(MBox::from_raw_parts(value, len))
    }

    /// Converts the string into raw bytes.
    pub fn into_bytes(self) -> MBox<[u8]> {
        unsafe { MBox::from_raw(Self::into_raw(self) as *mut [u8]) }
    }

    /// Creates a string from raw bytes.
    ///
    /// # Safety
    ///
    /// The raw bytes must be valid UTF-8.
    pub unsafe fn from_utf8_unchecked(bytes: MBox<[u8]>) -> MBox<str> {
        Self::from_raw(MBox::into_raw(bytes) as *mut str)
    }

    /// Creates a string from raw bytes. If the content does not contain valid UTF-8, this method
    /// returns an `Err`.
    pub fn from_utf8(bytes: MBox<[u8]>) -> Result<MBox<str>, Utf8Error> {
        from_utf8(&bytes)?;
        unsafe { Ok(Self::from_utf8_unchecked(bytes)) }
    }
}

impl Default for MBox<str> {
    fn default() -> Self {
        unsafe { Self::from_raw_utf8_parts_unchecked(gen_malloc(0).as_ptr(), 0) }
    }
}

impl Clone for MBox<str> {
    fn clone(&self) -> Self {
        Self::from(&**self)
    }
}

impl From<&str> for MBox<str> {
    /// Creates a new `malloc`-boxed string by cloning the content of an existing string slice.
    fn from(string: &str) -> Self {
        let len = string.len();
        let new_slice = gen_malloc(len).as_ptr();
        // SAFETY: `new_slice` is not null, allocated with size fitting `string`,
        // and also `string` is guaranteed to be UTF-8.
        unsafe {
            copy_nonoverlapping(string.as_ptr(), new_slice, len);
            Self::from_raw_utf8_parts_unchecked(new_slice, len)
        }
    }
}

#[test]
fn test_string_from_bytes() {
    let bytes = MBox::from_slice(b"abcdef\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89");
    let string = MBox::from_utf8(bytes).unwrap();
    assert_eq!(&*string, "abcdef一二三");
    assert_eq!(string, MBox::<str>::from("abcdef一二三"));
    let bytes = string.into_bytes();
    assert_eq!(&*bytes, b"abcdef\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89");
}

#[test]
fn test_string_with_internal_nul() {
    let string = MBox::<str>::from("ab\0c");
    assert_eq!(&*string, "ab\0c");
}

#[test]
fn test_non_utf8() {
    let bytes = MBox::from_slice(b"\x88\x88\x88\x88");
    let string = MBox::from_utf8(bytes);
    assert!(string.is_err());
}

#[test]
fn test_default_str() {
    assert_eq!(MBox::<str>::default(), MBox::<str>::from(""));
}

#[test]
#[should_panic(expected = "panic on clone")]
fn test_panic_on_clone_slice() {
    let mbox: MBox<[PanicOnClone]> = once(PanicOnClone::default()).collect();
    let _ = mbox.clone();
}

//}}}
