%define dracutlibdir %{_prefix}/lib/dracut
%bcond_without check
%global __cargo_skip_build 0
%global __cargo_is_lib() false
%global with_bundled 1
%global with_packit 0
%global forgeurl https://github.com/fedora-iot/fido-device-onboard-rs
%global rpmdocsdir docs-rpms

Version:        0.4.9

%forgemeta

Name:           fido-device-onboard
Release:        1%{?dist}
Summary:        An implementation of the FIDO Device Onboard Specification written in rust

# Apache-2.0
# Apache-2.0 OR BSL-1.0
# Apache-2.0 OR ISC OR MIT
# Apache-2.0 OR MIT
# (Apache-2.0 OR MIT) AND BSD-3-Clause
# Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT
# BSD-2-Clause
# BSD-3-Clause
# CC0-1.0
# CC0-1.0 OR Apache-2.0
# ISC
# MIT
# MIT OR Apache-2.0
# MIT OR Apache-2.0 OR Zlib
# MPL-2.0
# Unlicense OR MIT
# Zlib OR Apache-2.0 OR MIT

License:        Apache-2.0 and BSD and MIT
URL:            %{forgeurl}
Source:         %{forgesource}
# this is a basic script to generate the vendor tarfile from the source git.
Source1:        make-vendored-tarfile.sh
%if ! 0%{?with_packit}
%if "%{?commit}" != ""
Source2:        %{name}-rs-%{commit}-vendor.tar.gz
%else
Source2:        %{name}-rs-%{version}-vendor.tar.gz
%endif
%endif

ExclusiveArch:  %{rust_arches}
# RHBZ 1869980
ExcludeArch:    s390x i686 %{power64}

%if 0%{?rhel} && !0%{?eln}
BuildRequires:  rust-toolset
%else
BuildRequires:  rust-packaging
%endif
BuildRequires: systemd-rpm-macros
BuildRequires: openssl-devel >= 3.0.1-12
BuildRequires: golang
BuildRequires: tpm2-tss-devel
BuildRequires: cryptsetup-devel
BuildRequires: clang-devel
BuildRequires: make
BuildRequires: python3-docutils
# List of bundled crate in vendor tarball, generated with:
# cargo metadata --locked --format-version 1 | CRATE_NAME="fido-device-onboard-rs" ./bundled-provides.jq
# TODO: fido is multi crate, let's investigate how to do this properly...
Provides: bundled(crate(ahash)) = 0.7.6
Provides: bundled(crate(aho-corasick)) = 0.7.20
Provides: bundled(crate(android_system_properties)) = 0.1.5
Provides: bundled(crate(anyhow)) = 1.0.70
Provides: bundled(crate(arrayref)) = 0.3.7
Provides: bundled(crate(arrayvec)) = 0.5.2
Provides: bundled(crate(assert-str)) = 0.1.0
Provides: bundled(crate(async-lock)) = 2.7.0
Provides: bundled(crate(async-session)) = 3.0.0
Provides: bundled(crate(async-trait)) = 0.1.68
Provides: bundled(crate(atty)) = 0.2.14
Provides: bundled(crate(autocfg)) = 1.1.0
Provides: bundled(crate(aws-nitro-enclaves-cose)) = 0.4.0
Provides: bundled(crate(base64)) = 0.13.1
Provides: bundled(crate(base64)) = 0.21.0
Provides: bundled(crate(bincode)) = 1.3.3
Provides: bundled(crate(bindgen)) = 0.63.0
Provides: bundled(crate(bitfield)) = 0.13.2
Provides: bundled(crate(bitflags)) = 1.3.2
Provides: bundled(crate(blake3)) = 0.3.8
Provides: bundled(crate(block-buffer)) = 0.9.0
Provides: bundled(crate(block-buffer)) = 0.10.4
Provides: bundled(crate(bstr)) = 1.4.0
Provides: bundled(crate(buf_redux)) = 0.8.4
Provides: bundled(crate(bumpalo)) = 3.12.0
Provides: bundled(crate(byteorder)) = 1.4.3
Provides: bundled(crate(bytes)) = 1.4.0
Provides: bundled(crate(cbindgen)) = 0.24.3
Provides: bundled(crate(cc)) = 1.0.79
Provides: bundled(crate(cexpr)) = 0.6.0
Provides: bundled(crate(cfg-if)) = 0.1.10
Provides: bundled(crate(cfg-if)) = 1.0.0
Provides: bundled(crate(chrono)) = 0.4.24
Provides: bundled(crate(chrono-tz)) = 0.6.1
Provides: bundled(crate(chrono-tz-build)) = 0.0.2
Provides: bundled(crate(ciborium)) = 0.2.0
Provides: bundled(crate(ciborium-io)) = 0.2.0
Provides: bundled(crate(ciborium-ll)) = 0.2.0
Provides: bundled(crate(clang-sys)) = 1.6.0
Provides: bundled(crate(clap)) = 3.2.23
Provides: bundled(crate(clap)) = 4.1.14
Provides: bundled(crate(clap_builder)) = 4.1.14
Provides: bundled(crate(clap_derive)) = 4.1.14
Provides: bundled(crate(clap_lex)) = 0.2.4
Provides: bundled(crate(clap_lex)) = 0.4.0
Provides: bundled(crate(codespan-reporting)) = 0.11.1
Provides: bundled(crate(config)) = 0.13.3
Provides: bundled(crate(constant_time_eq)) = 0.1.5
Provides: bundled(crate(core-foundation)) = 0.9.3
Provides: bundled(crate(core-foundation-sys)) = 0.8.3
Provides: bundled(crate(cpufeatures)) = 0.2.6
Provides: bundled(crate(crypto-common)) = 0.1.6
Provides: bundled(crate(crypto-mac)) = 0.8.0
Provides: bundled(crate(crypto-mac)) = 0.11.1
Provides: bundled(crate(ctor)) = 0.1.26
Provides: bundled(crate(cxx)) = 1.0.94
Provides: bundled(crate(cxx-build)) = 1.0.94
Provides: bundled(crate(cxxbridge-flags)) = 1.0.94
Provides: bundled(crate(cxxbridge-macro)) = 1.0.94
Provides: bundled(crate(dashmap)) = 5.4.0
Provides: bundled(crate(deunicode)) = 0.4.3
Provides: bundled(crate(devicemapper)) = 0.33.2
Provides: bundled(crate(devicemapper-sys)) = 0.1.5
Provides: bundled(crate(diff)) = 0.1.13
Provides: bundled(crate(digest)) = 0.9.0
Provides: bundled(crate(digest)) = 0.10.6
Provides: bundled(crate(dlv-list)) = 0.3.0
Provides: bundled(crate(either)) = 1.8.1
Provides: bundled(crate(encoding_rs)) = 0.8.32
Provides: bundled(crate(enumflags2)) = 0.7.5
Provides: bundled(crate(enumflags2_derive)) = 0.7.4
Provides: bundled(crate(env_logger)) = 0.7.1
Provides: bundled(crate(env_logger)) = 0.9.3
Provides: bundled(crate(errno)) = 0.2.8
Provides: bundled(crate(errno-dragonfly)) = 0.1.2
Provides: bundled(crate(event-listener)) = 2.5.3
Provides: bundled(crate(fastrand)) = 1.9.0
Provides: bundled(crate(fdo-admin-tool)) = 0.4.9
Provides: bundled(crate(fdo-client-linuxapp)) = 0.4.9
Provides: bundled(crate(fdo-data)) = 0.4.9
Provides: bundled(crate(fdo-data-formats)) = 0.4.9
Provides: bundled(crate(fdo-http-wrapper)) = 0.4.9
Provides: bundled(crate(fdo-manufacturing-client)) = 0.4.9
Provides: bundled(crate(fdo-manufacturing-server)) = 0.4.9
Provides: bundled(crate(fdo-owner-onboarding-server)) = 0.4.9
Provides: bundled(crate(fdo-owner-tool)) = 0.4.9
Provides: bundled(crate(fdo-rendezvous-server)) = 0.4.9
Provides: bundled(crate(fdo-serviceinfo-api-server)) = 0.4.9
Provides: bundled(crate(fdo-store)) = 0.4.9
Provides: bundled(crate(fdo-util)) = 0.4.9
Provides: bundled(crate(fnv)) = 1.0.7
Provides: bundled(crate(foreign-types)) = 0.3.2
Provides: bundled(crate(foreign-types-shared)) = 0.1.1
Provides: bundled(crate(form_urlencoded)) = 1.1.0
Provides: bundled(crate(futures)) = 0.3.27
Provides: bundled(crate(futures-channel)) = 0.3.27
Provides: bundled(crate(futures-core)) = 0.3.27
Provides: bundled(crate(futures-executor)) = 0.3.27
Provides: bundled(crate(futures-io)) = 0.3.27
Provides: bundled(crate(futures-macro)) = 0.3.27
Provides: bundled(crate(futures-sink)) = 0.3.27
Provides: bundled(crate(futures-task)) = 0.3.27
Provides: bundled(crate(futures-util)) = 0.3.27
Provides: bundled(crate(generic-array)) = 0.14.7
Provides: bundled(crate(getrandom)) = 0.2.8
Provides: bundled(crate(glob)) = 0.3.1
Provides: bundled(crate(globset)) = 0.4.10
Provides: bundled(crate(globwalk)) = 0.8.1
Provides: bundled(crate(h2)) = 0.3.16
Provides: bundled(crate(half)) = 1.8.2
Provides: bundled(crate(hashbrown)) = 0.12.3
Provides: bundled(crate(headers)) = 0.3.8
Provides: bundled(crate(headers-core)) = 0.2.0
Provides: bundled(crate(heck)) = 0.4.1
Provides: bundled(crate(hermit-abi)) = 0.1.19
Provides: bundled(crate(hermit-abi)) = 0.2.6
Provides: bundled(crate(hermit-abi)) = 0.3.1
Provides: bundled(crate(hex)) = 0.4.3
Provides: bundled(crate(hmac)) = 0.11.0
Provides: bundled(crate(hostname-validator)) = 1.1.1
Provides: bundled(crate(http)) = 0.2.9
Provides: bundled(crate(http-body)) = 0.4.5
Provides: bundled(crate(httparse)) = 1.8.0
Provides: bundled(crate(httpdate)) = 1.0.2
Provides: bundled(crate(humansize)) = 2.1.3
Provides: bundled(crate(humantime)) = 1.3.0
Provides: bundled(crate(humantime)) = 2.1.0
Provides: bundled(crate(hyper)) = 0.14.25
Provides: bundled(crate(hyper-tls)) = 0.5.0
Provides: bundled(crate(iana-time-zone)) = 0.1.54
Provides: bundled(crate(iana-time-zone-haiku)) = 0.1.1
Provides: bundled(crate(idna)) = 0.3.0
Provides: bundled(crate(ignore)) = 0.4.20
Provides: bundled(crate(indexmap)) = 1.9.3
Provides: bundled(crate(instant)) = 0.1.12
Provides: bundled(crate(integration-tests)) = 0.4.9
Provides: bundled(crate(io-lifetimes)) = 1.0.9
Provides: bundled(crate(ipnet)) = 2.7.2
Provides: bundled(crate(is-terminal)) = 0.4.5
Provides: bundled(crate(itoa)) = 1.0.6
Provides: bundled(crate(js-sys)) = 0.3.61
Provides: bundled(crate(json5)) = 0.4.1
Provides: bundled(crate(lazy_static)) = 1.4.0
Provides: bundled(crate(lazycell)) = 1.3.0
Provides: bundled(crate(libc)) = 0.2.140
Provides: bundled(crate(libcryptsetup-rs)) = 0.6.1
Provides: bundled(crate(libcryptsetup-rs-sys)) = 0.2.3
Provides: bundled(crate(libloading)) = 0.7.4
Provides: bundled(crate(libm)) = 0.2.6
Provides: bundled(crate(link-cplusplus)) = 1.0.8
Provides: bundled(crate(linked-hash-map)) = 0.5.6
Provides: bundled(crate(linux-raw-sys)) = 0.1.4
Provides: bundled(crate(lock_api)) = 0.4.9
Provides: bundled(crate(log)) = 0.4.17
Provides: bundled(crate(maplit)) = 1.0.2
Provides: bundled(crate(mbox)) = 0.6.0
Provides: bundled(crate(memchr)) = 2.5.0
Provides: bundled(crate(memoffset)) = 0.7.1
Provides: bundled(crate(mime)) = 0.3.17
Provides: bundled(crate(mime_guess)) = 2.0.4
Provides: bundled(crate(minimal-lexical)) = 0.2.1
Provides: bundled(crate(mio)) = 0.8.6
Provides: bundled(crate(multipart)) = 0.18.0
Provides: bundled(crate(native-tls)) = 0.2.11
Provides: bundled(crate(nix)) = 0.26.2
Provides: bundled(crate(nom)) = 7.1.3
Provides: bundled(crate(num-derive)) = 0.3.3
Provides: bundled(crate(num-integer)) = 0.1.45
Provides: bundled(crate(num-traits)) = 0.2.15
Provides: bundled(crate(num_cpus)) = 1.15.0
Provides: bundled(crate(oid)) = 0.2.1
Provides: bundled(crate(once_cell)) = 1.17.1
Provides: bundled(crate(opaque-debug)) = 0.3.0
Provides: bundled(crate(openssl)) = 0.10.48
Provides: bundled(crate(openssl-kdf)) = 0.4.1
Provides: bundled(crate(openssl-macros)) = 0.1.0
Provides: bundled(crate(openssl-probe)) = 0.1.5
Provides: bundled(crate(openssl-sys)) = 0.9.83
Provides: bundled(crate(ordered-multimap)) = 0.4.3
Provides: bundled(crate(os_str_bytes)) = 6.5.0
Provides: bundled(crate(output_vt100)) = 0.1.3
Provides: bundled(crate(parking_lot)) = 0.12.1
Provides: bundled(crate(parking_lot_core)) = 0.9.7
Provides: bundled(crate(parse-zoneinfo)) = 0.3.0
Provides: bundled(crate(passwd)) = 0.0.1
Provides: bundled(crate(paste)) = 1.0.12
Provides: bundled(crate(pathdiff)) = 0.2.1
Provides: bundled(crate(peeking_take_while)) = 0.1.2
Provides: bundled(crate(pem)) = 1.1.1
Provides: bundled(crate(percent-encoding)) = 2.2.0
Provides: bundled(crate(pest)) = 2.5.6
Provides: bundled(crate(pest_derive)) = 2.5.6
Provides: bundled(crate(pest_generator)) = 2.5.6
Provides: bundled(crate(pest_meta)) = 2.5.6
Provides: bundled(crate(phf)) = 0.10.1
Provides: bundled(crate(phf_codegen)) = 0.10.0
Provides: bundled(crate(phf_generator)) = 0.10.0
Provides: bundled(crate(phf_shared)) = 0.10.0
Provides: bundled(crate(picky-asn1)) = 0.3.3
Provides: bundled(crate(picky-asn1-der)) = 0.2.5
Provides: bundled(crate(picky-asn1-x509)) = 0.6.1
Provides: bundled(crate(pin-project)) = 1.0.12
Provides: bundled(crate(pin-project-internal)) = 1.0.12
Provides: bundled(crate(pin-project-lite)) = 0.2.9
Provides: bundled(crate(pin-utils)) = 0.1.0
Provides: bundled(crate(pkg-config)) = 0.3.26
Provides: bundled(crate(ppv-lite86)) = 0.2.17
Provides: bundled(crate(pretty_assertions)) = 1.3.0
Provides: bundled(crate(pretty_env_logger)) = 0.4.0
Provides: bundled(crate(proc-macro2)) = 1.0.54
Provides: bundled(crate(quick-error)) = 1.2.3
Provides: bundled(crate(quote)) = 1.0.26
Provides: bundled(crate(rand)) = 0.8.5
Provides: bundled(crate(rand_chacha)) = 0.3.1
Provides: bundled(crate(rand_core)) = 0.6.4
Provides: bundled(crate(redox_syscall)) = 0.2.16
Provides: bundled(crate(regex)) = 1.7.3
Provides: bundled(crate(regex-syntax)) = 0.6.29
Provides: bundled(crate(reqwest)) = 0.11.16
Provides: bundled(crate(retry)) = 1.3.1
Provides: bundled(crate(ron)) = 0.7.1
Provides: bundled(crate(rust-ini)) = 0.18.0
Provides: bundled(crate(rustc-hash)) = 1.1.0
Provides: bundled(crate(rustc_version)) = 0.3.3
Provides: bundled(crate(rustix)) = 0.36.11
Provides: bundled(crate(rustls-pemfile)) = 0.2.1
Provides: bundled(crate(ryu)) = 1.0.13
Provides: bundled(crate(safemem)) = 0.3.3
Provides: bundled(crate(same-file)) = 1.0.6
Provides: bundled(crate(schannel)) = 0.1.21
Provides: bundled(crate(scoped-tls)) = 1.0.1
Provides: bundled(crate(scopeguard)) = 1.1.0
Provides: bundled(crate(scratch)) = 1.0.5
Provides: bundled(crate(secrecy)) = 0.8.0
Provides: bundled(crate(security-framework)) = 2.8.2
Provides: bundled(crate(security-framework-sys)) = 2.8.0
Provides: bundled(crate(semver)) = 0.11.0
Provides: bundled(crate(semver)) = 1.0.17
Provides: bundled(crate(semver-parser)) = 0.10.2
Provides: bundled(crate(serde)) = 1.0.159
Provides: bundled(crate(serde_bytes)) = 0.11.9
Provides: bundled(crate(serde_cbor)) = 0.11.2
Provides: bundled(crate(serde_derive)) = 1.0.159
Provides: bundled(crate(serde_json)) = 1.0.95
Provides: bundled(crate(serde_repr)) = 0.1.12
Provides: bundled(crate(serde_tuple)) = 0.5.0
Provides: bundled(crate(serde_tuple_macros)) = 0.5.0
Provides: bundled(crate(serde_urlencoded)) = 0.7.1
Provides: bundled(crate(serde_with)) = 1.14.0
Provides: bundled(crate(serde_yaml)) = 0.9.19
Provides: bundled(crate(serial_test)) = 1.0.0
Provides: bundled(crate(serial_test_derive)) = 1.0.0
Provides: bundled(crate(sha-1)) = 0.10.1
Provides: bundled(crate(sha1)) = 0.10.5
Provides: bundled(crate(sha2)) = 0.9.9
Provides: bundled(crate(sha2)) = 0.10.6
Provides: bundled(crate(shlex)) = 1.1.0
Provides: bundled(crate(signal-hook-registry)) = 1.4.1
Provides: bundled(crate(siphasher)) = 0.3.10
Provides: bundled(crate(slab)) = 0.4.8
Provides: bundled(crate(slug)) = 0.1.4
Provides: bundled(crate(smallvec)) = 1.10.0
Provides: bundled(crate(socket2)) = 0.4.9
Provides: bundled(crate(stable_deref_trait)) = 1.2.0
Provides: bundled(crate(static_assertions)) = 1.1.0
Provides: bundled(crate(strsim)) = 0.10.0
Provides: bundled(crate(subtle)) = 2.4.1
Provides: bundled(crate(syn)) = 1.0.109
Provides: bundled(crate(syn)) = 2.0.11
Provides: bundled(crate(sys-info)) = 0.9.1
Provides: bundled(crate(target-lexicon)) = 0.12.6
Provides: bundled(crate(tempfile)) = 3.4.0
Provides: bundled(crate(tera)) = 1.18.1
Provides: bundled(crate(termcolor)) = 1.2.0
Provides: bundled(crate(textwrap)) = 0.16.0
Provides: bundled(crate(thiserror)) = 1.0.40
Provides: bundled(crate(thiserror-impl)) = 1.0.40
Provides: bundled(crate(thread_local)) = 1.1.4
Provides: bundled(crate(time)) = 0.3.20
Provides: bundled(crate(time-core)) = 0.1.0
Provides: bundled(crate(tinyvec)) = 1.6.0
Provides: bundled(crate(tinyvec_macros)) = 0.1.1
Provides: bundled(crate(tokio)) = 1.27.0
Provides: bundled(crate(tokio-macros)) = 2.0.0
Provides: bundled(crate(tokio-native-tls)) = 0.3.1
Provides: bundled(crate(tokio-stream)) = 0.1.12
Provides: bundled(crate(tokio-tungstenite)) = 0.17.2
Provides: bundled(crate(tokio-util)) = 0.7.7
Provides: bundled(crate(toml)) = 0.5.11
Provides: bundled(crate(tower-service)) = 0.3.2
Provides: bundled(crate(tracing)) = 0.1.37
Provides: bundled(crate(tracing-core)) = 0.1.30
Provides: bundled(crate(try-lock)) = 0.2.4
Provides: bundled(crate(tss-esapi)) = 7.2.0
Provides: bundled(crate(tss-esapi-sys)) = 0.4.0
Provides: bundled(crate(tungstenite)) = 0.17.3
Provides: bundled(crate(twoway)) = 0.1.8
Provides: bundled(crate(typenum)) = 1.16.0
Provides: bundled(crate(ucd-trie)) = 0.1.5
Provides: bundled(crate(uncased)) = 0.9.7
Provides: bundled(crate(unic-char-property)) = 0.9.0
Provides: bundled(crate(unic-char-range)) = 0.9.0
Provides: bundled(crate(unic-common)) = 0.9.0
Provides: bundled(crate(unic-segment)) = 0.9.0
Provides: bundled(crate(unic-ucd-segment)) = 0.9.0
Provides: bundled(crate(unic-ucd-version)) = 0.9.0
Provides: bundled(crate(unicase)) = 2.6.0
Provides: bundled(crate(unicode-bidi)) = 0.3.13
Provides: bundled(crate(unicode-ident)) = 1.0.8
Provides: bundled(crate(unicode-normalization)) = 0.1.22
Provides: bundled(crate(unicode-width)) = 0.1.10
Provides: bundled(crate(unsafe-libyaml)) = 0.2.7
Provides: bundled(crate(url)) = 2.3.1
Provides: bundled(crate(users)) = 0.11.0
Provides: bundled(crate(utf-8)) = 0.7.6
Provides: bundled(crate(uuid)) = 1.3.0
Provides: bundled(crate(vcpkg)) = 0.2.15
Provides: bundled(crate(version_check)) = 0.9.4
Provides: bundled(crate(walkdir)) = 2.3.3
Provides: bundled(crate(want)) = 0.3.0
Provides: bundled(crate(warp)) = 0.3.3
Provides: bundled(crate(warp-sessions)) = 1.0.18
Provides: bundled(crate(wasi)) = 0.11.0+wasi_snapshot_preview1
Provides: bundled(crate(wasm-bindgen)) = 0.2.84
Provides: bundled(crate(wasm-bindgen-backend)) = 0.2.84
Provides: bundled(crate(wasm-bindgen-futures)) = 0.4.34
Provides: bundled(crate(wasm-bindgen-macro)) = 0.2.84
Provides: bundled(crate(wasm-bindgen-macro-support)) = 0.2.84
Provides: bundled(crate(wasm-bindgen-shared)) = 0.2.84
Provides: bundled(crate(web-sys)) = 0.3.61
Provides: bundled(crate(winapi)) = 0.3.9
Provides: bundled(crate(winapi-i686-pc-windows-gnu)) = 0.4.0
Provides: bundled(crate(winapi-util)) = 0.1.5
Provides: bundled(crate(winapi-x86_64-pc-windows-gnu)) = 0.4.0
Provides: bundled(crate(windows)) = 0.46.0
Provides: bundled(crate(windows-sys)) = 0.42.0
Provides: bundled(crate(windows-sys)) = 0.45.0
Provides: bundled(crate(windows-targets)) = 0.42.2
Provides: bundled(crate(windows_aarch64_gnullvm)) = 0.42.2
Provides: bundled(crate(windows_aarch64_msvc)) = 0.42.2
Provides: bundled(crate(windows_i686_gnu)) = 0.42.2
Provides: bundled(crate(windows_i686_msvc)) = 0.42.2
Provides: bundled(crate(windows_x86_64_gnu)) = 0.42.2
Provides: bundled(crate(windows_x86_64_gnullvm)) = 0.42.2
Provides: bundled(crate(windows_x86_64_msvc)) = 0.42.2
Provides: bundled(crate(winreg)) = 0.10.1
Provides: bundled(crate(xattr)) = 1.0.0
Provides: bundled(crate(yaml-rust)) = 0.4.5
Provides: bundled(crate(yansi)) = 0.5.1
Provides: bundled(crate(zeroize)) = 1.6.0
Provides: bundled(crate(zeroize_derive)) = 1.4.1

%description
%{summary}.

%prep
%forgeautosetup
%if ! 0%{?with_packit}
tar xvf %{SOURCE2}
%endif
%if ! 0%{?with_bundled}
%cargo_prep
%else
mkdir -p .cargo
cat >.cargo/config << EOF
[build]
rustc = "%{__rustc}"
rustdoc = "%{__rustdoc}"
%if 0%{?rhel} && !0%{?eln}
rustflags = %{__global_rustflags_toml}
%else
rustflags = "%{__global_rustflags_toml}"
%endif

[install]
root = "%{buildroot}%{_prefix}"
 
[term]
verbose = true
 
[source.crates-io]
replace-with = "vendored-sources"
 
[source.vendored-sources]
directory = "vendor"
EOF
%endif

%if ! 0%{?with_bundled}
%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
%if 0%{?rhel} && !0%{?eln}
%cargo_build \
-F openssl-kdf/deny_custom
%else
%cargo_build
%endif
make man

%install
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-client-linuxapp
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-client
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-onboarding-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-rendezvous-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-serviceinfo-api-server
# duplicates as needed by AIO command
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-tool
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-admin-tool
install -D -m 0755 -t %{buildroot}%{_bindir} target/release/fdo-owner-tool
install -D -m 0755 -t %{buildroot}%{_bindir} target/release/fdo-admin-tool
install -D -m 0644 -t %{buildroot}%{_unitdir} examples/systemd/*
# we do not need the rendezvous-info.yml for the AIO command, add everything else
install -D -m 0644 -t %{buildroot}%{_docdir}/examples examples/config/manufacturing-server.yml
install -D -m 0644 -t %{buildroot}%{_docdir}/examples examples/config/owner-onboarding-server.yml
install -D -m 0644 -t %{buildroot}%{_docdir}/examples examples/config/rendezvous-server.yml
install -D -m 0644 -t %{buildroot}%{_docdir}/examples examples/config/serviceinfo-api-server.yml
mkdir -p %{buildroot}%{_sysconfdir}/fdo
# 52fdo
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/module-setup.sh
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-generator
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-service
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client.service
# man pages
install -D -m 0644 -t %{buildroot}%{_mandir}/man1 %{rpmdocsdir}/*.1

%package -n fdo-init
Summary: dracut module for device initialization
Requires: openssl-libs >= 3.0.1-12
%description -n fdo-init
%{summary}

%files -n fdo-init
%license LICENSE
%{_mandir}/man1/fdo-init.1*
%{dracutlibdir}/modules.d/52fdo/*
%{_libexecdir}/fdo/fdo-manufacturing-client

%package -n fdo-owner-onboarding-server
Summary: FDO Owner Onboarding Server implementation
Requires: openssl-libs >= 3.0.1-12
%description -n fdo-owner-onboarding-server
%{summary}

%files -n fdo-owner-onboarding-server
%license LICENSE
%{_mandir}/man1/fdo-owner-onboarding-server.1*
%{_libexecdir}/fdo/fdo-owner-onboarding-server
%{_libexecdir}/fdo/fdo-serviceinfo-api-server
%{_docdir}/examples/owner-onboarding-server.yml
%{_docdir}/examples/serviceinfo-api-server.yml
%{_unitdir}/fdo-owner-onboarding-server.service
%{_unitdir}/fdo-serviceinfo-api-server.service

%post -n fdo-owner-onboarding-server
%systemd_post fdo-owner-onboarding-server.service
%systemd_post fdo-serviceinfo-api-server.service

%preun -n fdo-owner-onboarding-server
%systemd_preun fdo-owner-onboarding-server.service
%systemd_preun fdo-serviceinfo-api-server.service

%postun -n fdo-owner-onboarding-server
%systemd_postun_with_restart fdo-owner-onboarding-server.service
%systemd_postun_with_restart fdo-serviceinfo-api-server.service

%package -n fdo-rendezvous-server
Summary: FDO Rendezvous Server implementation
%description -n fdo-rendezvous-server
%{summary}

%files -n fdo-rendezvous-server
%license LICENSE
%{_mandir}/man1/fdo-rendezvous-server.1*
%{_libexecdir}/fdo/fdo-rendezvous-server
%{_docdir}/examples/rendezvous-server.yml
%{_unitdir}/fdo-rendezvous-server.service

%post -n fdo-rendezvous-server
%systemd_post fdo-rendezvous-server.service

%preun -n fdo-rendezvous-server
%systemd_preun fdo-rendezvous-server.service

%postun -n fdo-rendezvous-server
%systemd_postun_with_restart fdo-rendezvous-server.service

%package -n fdo-manufacturing-server
Summary: FDO Manufacturing Server implementation
Requires: openssl-libs >= 3.0.1-12
%description -n fdo-manufacturing-server
%{summary}

%files -n fdo-manufacturing-server
%license LICENSE
%{_mandir}/man1/fdo-manufacturing-server.1*
%{_libexecdir}/fdo/fdo-manufacturing-server
%{_docdir}/examples/manufacturing-server.yml
%{_unitdir}/fdo-manufacturing-server.service

%post -n fdo-manufacturing-server
%systemd_post fdo-manufacturing-server.service

%preun -n fdo-manufacturing-server
%systemd_preun fdo-manufacturing-server.service

%postun -n fdo-manufacturing-server
%systemd_postun_with_restart fdo-manufacturing-server.service

%package -n fdo-client
Summary: FDO Client implementation
Requires: openssl-libs >= 3.0.1-12
Requires: clevis
Requires: clevis-luks
Requires: cryptsetup
%description -n fdo-client
%{summary}

%files -n fdo-client
%license LICENSE
%{_mandir}/man1/fdo-client.1*
%{_libexecdir}/fdo/fdo-client-linuxapp
%{_unitdir}/fdo-client-linuxapp.service

%post -n fdo-client
%systemd_post fdo-client-linuxapp.service

%preun -n fdo-client
%systemd_preun fdo-client-linuxapp.service

%postun -n fdo-client
%systemd_postun_with_restart fdo-client-linuxapp.service

%package -n fdo-owner-cli
Summary: FDO Owner tools implementation
%description -n fdo-owner-cli
%{summary}

%files -n fdo-owner-cli
%license LICENSE
%{_mandir}/man1/fdo-owner-cli.1*
%{_bindir}/fdo-owner-tool
%{_libexecdir}/fdo/fdo-owner-tool

%package -n fdo-admin-cli
Summary: FDO admin tools implementation
Requires: fdo-manufacturing-server
Requires: fdo-init
Requires: fdo-client
Requires: fdo-rendezvous-server
Requires: fdo-owner-onboarding-server
Requires: fdo-owner-cli
%description -n fdo-admin-cli
%{summary}

%files -n fdo-admin-cli
%license LICENSE
%{_mandir}/man1/fdo-admin-cli.1*
%dir %{_sysconfdir}/fdo
%{_bindir}/fdo-admin-tool
%{_libexecdir}/fdo/fdo-admin-tool
%{_unitdir}/fdo-aio.service

%post -n fdo-admin-cli
%systemd_post fdo-aio.service

%preun -n fdo-admin-cli
%systemd_preun fdo-aio.service

%postun -n fdo-admin-cli
%systemd_postun_with_restart fdo-aio.service

%changelog
* Wed Feb 15 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.8-1
- Update to 0.4.8

* Wed Nov 30 2022 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.7-1
- Update to 0.4.7

* Thu Oct 06 2022 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.6-1
- Update to 0.4.6

* Tue Mar 15 2022 Antonio Murdaca <runcom@linux.com> - 0.4.5-1
- Rebase to 0.4.5

* Thu Feb 24 2022 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.4.0-1
- Rebase to 0.4.0

* Tue Feb 1 2022 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-1
- Rebase to 0.3.0

* Fri Dec 10 2021 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.2.0-1
- Rebase to 0.2.0

* Tue Oct 5 2021 Antonio Murdaca <amurdaca@redhat.com> - 0.1.0-1
- initial release
