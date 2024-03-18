# Change Log
All user visible changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/), as described
for Rust libraries in [RFC #1105](https://github.com/rust-lang/rfcs/blob/master/text/1105-api-evolution.md)

## [0.4.8] 2023-04-18

## Fixed

- Added `wldap` as dependency for the vcpk installation on windows as that's now required there

## [0.4.5] 2018-05-09

### Added

- Linking can now be dynamically handled per-target by specifying the `TARGET`
  environment variable and `PQ_LIB_STATIC_$TARGET` environment variable.

- The path to `pg_config` can now be dynamically handled per-target by
  specifying the `TARGET` environment variable and `PG_CONFIG_$TARGET`
  environment variable.

## [0.4.3] 2017-03-10

### Fixed

- Linking on the msvc toolchain will no longer attempt to statically link

## [0.4.2] 2017-02-19

### Fixed

- Improved linking on Windows, particularly with the msvc toolchain.

## [0.4.1] 2017-02-19

### Fixed

- Properly specified the build script

## [0.4.0] 2017-02-19 [YANKED]

### Changed

- Bindings are no longer generated at compile time. Requiring clang 3.9 caused
  too many issues for too many users, and requiring `syntex_syntax` increased
  compile time too much.

## [0.3.2] 2017-02-16

### Fixed

- Fixed an issue when building on mac against postgres from homebrew

## [0.3.1] 2017-02-16

### Fixed

- Fixed an issue when building on mac against postgres from homebrew

- Fixed an issue with locating header files on linux

## [0.3.0] 2017-02-16

### Changed

- Bindings are now generated when the library is built, rather than being
  vendored ahead of time.

- `libc` is no longer used. Anywhere that `libc::some_type` was expected,
  `std::os::raw::some_type` is now used instead.

- The build script will no longer attempt to canonicalize symlinks on MacOS.

## [0.2.7] 2016-12-10

### Changed

- `pkg-config` is disabled by default. It can be enabled by adding `features =
  ["pkg-config"]` to your `Cargo.toml`.

## [0.2.6] 2016-12-10

### Added

- We will attempt to use `pkg-config` to locate libpq before falling back to
  `pg_config`.

## [0.2.5] 2016-12-10

- No changes. Accidental release on the wrong commit.

## [0.2.4] 2016-11-22

### Added

- `pq` will be statically linked if the environment variable `PQ_LIB_STATIC` is
  set.

## [0.2.3] 2016-08-12

### Changed

- On Mac if `pg_config` points to a directory where `libpq.dylib` is a symlink,
  we will now attempt to find the canonical directory to link against. This
  means that for installations using homebrew,
  `/usr/local/Cellar/postgresql/version/lib` will be added to `DYLD_LIBRARY_PATH`
  instead of `/usr/local/lib`

## [0.2.2] 2016-07-30

### Added

- The directory containing libpq for linking can now be specified via the
  `PQ_LIB_DIR` environment variable.
