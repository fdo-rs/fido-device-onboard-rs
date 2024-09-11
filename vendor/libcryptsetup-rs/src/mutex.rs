// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! # per-thread-mutex
//!
//! Synchronization lock intended for thread unsafe C libraries.
//!
//! ## Rationale
//!
//! When working with certain C libraries, concurrent accesses are not safe. It can be problematic
//! to model this at the Rust level largely because language level support can't enforce everything
//! that's necessary to maintain safety in all cases.
//!
//! [`Send`][Send]/[`Sync`][Sync] can ensure that data structures are not used and sent across
//! threads which provides part of the puzzle. However for certain cases thread-unsafe libraries
//! can be used in a multithreaded context provided two conditions are upheld.
//!
//! 1. Data structures are thread-localized, meaning any resource that is created in a thread is
//!    never sent or used by another thread. This can be handled [`Send`]/[`Sync`].
//! 2. There can be no concurrent calls into the library. This is not addressed by Rust language
//!    level features.
//!
//! This crate aims to address requirement 2.
//!
//! ## How is it used?
//!
//! The intended use of this mutex is with lazy_static as a global variable in Rust bindings for
//! thread-unsafe C code. The mutex should be locked before each call into the library. This
//! ensures that there are never any concurrent accesses from separate threads which could lead to
//! unsafe behavior.
//!
//! ## How does it work?
//!
//! The lock keeps track of two pieces of data: the thread ID of the thread that currently has the
//! lock acquisition and the number of acquisitions currently active on the lock. Acquisitions from
//! the same thread ID are allowed at the same time and the lock available once all acquisitions
//! of the lock are released.
//!
//! ## Why is the same thread permitted to acquire the mutex multiple times?
//!
//! This largely stems from C's heavy use of callbacks. If a callback is built into a C API, it is
//! typical in Rust bindings to write the callback in Rust and to write a C shim to convert from C
//! to Rust data types. Consider the case of an API call that, in its implementation, calls a
//! callback where the callback also calls a Rust-wrapped API call. This is a safe usage of the
//! library, but would result in a double acquisition of a traditional mutex guarding calls into
//! the library. This lock allows both of those acquisitions to succeed without blocking,
//! preventing the deadlock that would be caused by a traditional mutex while still guard against
//! unsafe accesses of the library.

use std::{
    io,
    sync::atomic::{AtomicU32, Ordering},
};

use libc::gettid;
use log::trace;

pub struct PerThreadMutex {
    futex_word: AtomicU32,
    thread_id: AtomicU32,
    acquisitions: AtomicU32,
}

impl Default for PerThreadMutex {
    /// Create a new mutex.
    fn default() -> Self {
        PerThreadMutex {
            futex_word: AtomicU32::new(0),
            thread_id: AtomicU32::new(0),
            acquisitions: AtomicU32::new(0),
        }
    }
}

impl PerThreadMutex {
    /// Acquire a per-thread lock.
    ///
    /// The lock keeps track of the thread ID from which it is called. If a second acquire is called
    /// from the same mutex, `acquire()` will grant a lock to that caller as well. Number of
    /// acquisitions is tracked internally and the lock will be released when all acquisitions are
    /// dropped.
    pub fn acquire(&self) -> PerThreadMutexGuard<'_> {
        loop {
            if self
                .futex_word
                .compare_exchange_weak(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                == Ok(0)
            {
                let thread_id = unsafe { libc::gettid() } as u32;
                assert_eq!(self.acquisitions.fetch_add(1, Ordering::Relaxed), 0);
                assert_eq!(
                    self.thread_id.compare_exchange(
                        0,
                        thread_id,
                        Ordering::Relaxed,
                        Ordering::Relaxed
                    ),
                    Ok(0)
                );
                trace!("[{}] Acquired initial lock", thread_id);
                return PerThreadMutexGuard(self, thread_id);
            } else {
                let thread_id = unsafe { gettid() } as u32;
                if self.thread_id.load(Ordering::Relaxed) == thread_id {
                    let count = self.acquisitions.fetch_add(1, Ordering::Relaxed);
                    trace!("[{}] Acquired lock number {}", thread_id, count + 1);
                    return PerThreadMutexGuard(self, thread_id);
                } else {
                    trace!("[{}] Thread is waiting", unsafe { libc::gettid() });
                    match unsafe {
                        libc::syscall(
                            libc::SYS_futex,
                            self.futex_word.as_ptr(),
                            libc::FUTEX_WAIT,
                            1,
                            0,
                            0,
                            0,
                        )
                    } {
                        0 => (),
                        _ => match io::Error::last_os_error().raw_os_error() {
                            Some(libc::EINTR | libc::EAGAIN) => (),
                            Some(libc::EACCES) => {
                                unreachable!("Local variable is always readable")
                            }
                            Some(i) => unreachable!(
                                "Only EAGAIN, EACCES, and EINTR are returned by FUTEX_WAIT; got {}",
                                i
                            ),
                            None => unreachable!(),
                        },
                    }
                }
            }
        }
    }
}

/// Guard indicating that the per-thread lock is still acquired. Dropping this lock causes all
/// waiters to be woken up. This mutex is not fair so the lock will be acquired by
/// the first thread that requests the acquisition.
pub struct PerThreadMutexGuard<'a>(&'a PerThreadMutex, u32);

impl<'a> Drop for PerThreadMutexGuard<'a> {
    fn drop(&mut self) {
        let acquisitions = self.0.acquisitions.fetch_sub(1, Ordering::Relaxed);
        assert!(acquisitions > 0);
        if acquisitions == 1 {
            assert_eq!(
                self.0
                    .thread_id
                    .compare_exchange(self.1, 0, Ordering::Relaxed, Ordering::Relaxed),
                Ok(self.1)
            );
            assert_eq!(
                self.0
                    .futex_word
                    .compare_exchange(1, 0, Ordering::Relaxed, Ordering::Relaxed),
                Ok(1)
            );
            trace!("[{}] Unlocking mutex", self.1);
            let i = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.0.futex_word.as_ptr(),
                    libc::FUTEX_WAKE as i64,
                    libc::INT_MAX as i64,
                    0,
                    0,
                    0,
                )
            };
            trace!("[{}] Number of waiters woken: {}", self.1, i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{sync::Arc, thread::spawn};

    use env_logger::init;

    #[test]
    fn test_lock() {
        init();

        let mutex = Arc::new(PerThreadMutex::default());

        let mutex_clone = Arc::clone(&mutex);
        let handle1 = spawn(move || {
            let _guard1 = mutex_clone.acquire();
            let _guard2 = mutex_clone.acquire();
            let _guard3 = mutex_clone.acquire();
        });

        let mutex_clone = Arc::clone(&mutex);
        let handle2 = spawn(move || {
            let _guard1 = mutex_clone.acquire();
            let _guard2 = mutex_clone.acquire();
            let _guard3 = mutex_clone.acquire();
            let _guard4 = mutex_clone.acquire();
        });

        let mutex_clone = Arc::clone(&mutex);
        let handle3 = spawn(move || {
            let _guard1 = mutex_clone.acquire();
            let _guard2 = mutex_clone.acquire();
        });

        let mutex_clone = Arc::clone(&mutex);
        let handle4 = spawn(move || {
            let _guard1 = mutex_clone.acquire();
            let _guard2 = mutex_clone.acquire();
            let _guard3 = mutex_clone.acquire();
            let _guard4 = mutex_clone.acquire();
            let _guard5 = mutex_clone.acquire();
        });

        let mutex_clone = Arc::clone(&mutex);
        let handle5 = spawn(move || {
            let _guard1 = mutex_clone.acquire();
        });

        for handle in [handle1, handle2, handle3, handle4, handle5] {
            handle.join().unwrap();
        }
    }
}
