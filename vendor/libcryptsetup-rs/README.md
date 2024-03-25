[![Latest Version](https://img.shields.io/crates/v/libcryptsetup-rs.svg)](https://crates.io/crates/libcryptsetup-rs)
[![Documentation](https://docs.rs/libcryptsetup-rs/badge.svg)](https://docs.rs/libcryptsetup-rs/)

# libcryptsetup-rs

This crate provides Rust bindings for libcryptsetup.

### Note on thread-safety

libcryptsetup is *not* thread-safe and also depends on libraries that are not
thread-safe. Any use of libcryptsetup by default in a multithreaded environment will
result in undefined behavior.

As a workaround, this library provides a feature (`mutex`) to cause all calls to
libcryptsetup to acquire a crate-level mutex. This will enforce single threaded
access to all invocations of the libcryptsetup API.

Rust's decision to make pointers `!Send` should be respected. Any data structure that
contains a pointer is *not* safe to send across threads. Providing an `unsafe
impl Send {}` for any data structure provided by libcryptsetup-rs that is not `Send`
may result in undefined behavior.

### Building

The libcryptsetup bindings require some dependencies outside of cargo to build
properly:
1. cryptsetup (provided by `cryptsetup` on Fedora)
2. cryptsetup development headers (provided by `cryptsetup-devel` on Fedora)
3. libclang (provided by `clang` on Fedora)

### Sanity testing bindings

There is one test that actually invokes libcryptsetup and can be used for basic sanity
testing of the bindings as it will only succeed if low level bindings are correctly generated,
the high level bindings build, and libcryptsetup successfully encrypts a loopback device.

This can be invoked as follows:

```
make test-loopback
```
