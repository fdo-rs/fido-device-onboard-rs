%global dracutlibdir %{_prefix}/lib/dracut
%bcond_without check
%global combined_license Apache-2.0 AND (Apache-2.0 OR BSL-1.0) AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR MIT) AND ((Apache-2.0 OR MIT) AND BSD-3-Clause) AND (Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT) AND BSD-2-Clause AND BSD-3-Clause AND (CC0-1.0 OR Apache-2.0) AND (CC0-1.0 OR MIT-0 OR Apache-2.0) AND ISC AND MIT AND ((MIT OR Apache-2.0) AND Unicode-DFS-2016) AND (Apache-2.0 OR MIT OR Zlib) AND MPL-2.0 AND (Unlicense OR MIT)

Name:           fido-device-onboard
Version:        0.5.0
Release:        1%{?dist}
Summary:        A rust implementation of the FIDO Device Onboard Specification
License:        BSD-3-Clause

URL:            https://github.com/fdo-rs/fido-device-onboard-rs
Source0:        %{url}/archive/v%{version}/%{name}-rs-%{version}.tar.gz

# Because nobody cares
ExcludeArch: %{ix86}

%if 0%{?rhel}
BuildRequires:  rust-toolset
%else
BuildRequires:  rust-packaging
%endif
BuildRequires:  clang-devel
BuildRequires:  cryptsetup-devel
BuildRequires:  device-mapper-devel
BuildRequires:  libpq-devel
BuildRequires:  golang
BuildRequires:  openssl-devel >= 3.0.1-12
BuildRequires:  sqlite-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  tpm2-tss-devel

%description
%{summary}.

%prep
%autosetup -p1 -n %{name}-rs-%{version}

%if 0%{?rhel}
%if 0%{?rhel} >= 10
%cargo_prep -v vendor
%else
%cargo_prep -V 0
%endif
%endif

%if 0%{?fedora}
%cargo_prep
%generate_buildrequires
%cargo_generate_buildrequires -a
%endif

rm -f .cargo/cargo.toml

%build
%cargo_build \
-F openssl-kdf/deny_custom

%{?cargo_license_summary}
%{?cargo_license} > LICENSE.dependencies
%if 0%{?rhel} >= 10
%cargo_vendor_manifest
%endif

%install
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-client-linuxapp
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-client
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-onboarding-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-rendezvous-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-serviceinfo-api-server
install -D -m 0755 -t %{buildroot}%{_bindir} target/release/fdo-owner-tool
install -D -m 0755 -t %{buildroot}%{_bindir} target/release/fdo-admin-tool
install -D -m 0644 -t %{buildroot}%{_unitdir} examples/systemd/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo examples/config/*
# db sql files
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_manufacturing_server_postgres  migrations/migrations_manufacturing_server_postgres/2023-10-03-152801_create_db/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_manufacturing_server_sqlite  migrations/migrations_manufacturing_server_sqlite/2023-10-03-152801_create_db/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_owner_onboarding_server_postgres  migrations/migrations_owner_onboarding_server_postgres/2023-10-03-152801_create_db/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_owner_onboarding_server_sqlite  migrations/migrations_owner_onboarding_server_sqlite/2023-10-03-152801_create_db/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_rendezvous_server_postgres  migrations/migrations_rendezvous_server_postgres/2023-10-03-152801_create_db/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo/migrations/migrations_rendezvous_server_sqlite  migrations/migrations_rendezvous_server_sqlite/2023-10-03-152801_create_db/*
# duplicates as needed by AIO command so link them
mkdir -p %{buildroot}%{_bindir}
ln -sr %{buildroot}%{_bindir}/fdo-owner-tool  %{buildroot}%{_libexecdir}/fdo/fdo-owner-tool
ln -sr %{buildroot}%{_bindir}/fdo-admin-tool %{buildroot}%{_libexecdir}/fdo/fdo-admin-tool
# Create directories needed by the various services so we own them
mkdir -p %{buildroot}%{_sysconfdir}/fdo
mkdir -p %{buildroot}%{_sysconfdir}/fdo/keys
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/manufacturer_keys
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/manufacturing_sessions
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/owner_onboarding_sessions
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/owner_vouchers
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/rendezvous_registered
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/rendezvous_sessions
mkdir -p %{buildroot}%{_sysconfdir}/fdo/stores/serviceinfo_api_devices
mkdir -p %{buildroot}%{_sysconfdir}/fdo/manufacturing-server.conf.d
mkdir -p %{buildroot}%{_sysconfdir}/fdo/owner-onboarding-server.conf.d
mkdir -p %{buildroot}%{_sysconfdir}/fdo/rendezvous-server.conf.d
mkdir -p %{buildroot}%{_sysconfdir}/fdo/serviceinfo-api-server.conf.d
mkdir -p %{buildroot}%{_localstatedir}/lib/fdo
# Dracut manufacturing service
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/module-setup.sh
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-generator
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-service
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client.service

%package -n fdo-init
Summary: dracut module for device initialization
License: %combined_license
Requires: openssl-libs >= 3.0.1-12
Requires: dracut
%description -n fdo-init
%{summary}

%files -n fdo-init
%license LICENSE LICENSE.dependencies
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%{dracutlibdir}/modules.d/52fdo/
%{_libexecdir}/fdo/fdo-manufacturing-client

%package -n fdo-owner-onboarding-server
Summary: FDO Owner Onboarding Server implementation
License: %combined_license
Requires: openssl-libs >= 3.0.1-12
%description -n fdo-owner-onboarding-server
%{summary}

%files -n fdo-owner-onboarding-server
%license LICENSE LICENSE.dependencies
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%dir %{_sysconfdir}/fdo
%dir %{_sysconfdir}/fdo/keys
%dir %{_sysconfdir}/fdo/owner-onboarding-server.conf.d
%dir %{_sysconfdir}/fdo/serviceinfo-api-server.conf.d
%dir %{_sysconfdir}/fdo/stores
%dir %{_sysconfdir}/fdo/stores/owner_onboarding_sessions
%dir %{_sysconfdir}/fdo/stores/owner_vouchers
%dir %{_sysconfdir}/fdo/stores/serviceinfo_api_devices
%{_libexecdir}/fdo/fdo-owner-onboarding-server
%{_libexecdir}/fdo/fdo-serviceinfo-api-server
%dir %{_localstatedir}/lib/fdo
%dir %{_docdir}/fdo
%{_docdir}/fdo/device_specific_serviceinfo.yml
%{_docdir}/fdo/serviceinfo-api-server.yml
%{_docdir}/fdo/owner-onboarding-server.yml
%{_docdir}/fdo/migrations/migrations_owner_onboarding_server_postgres/*
%{_docdir}/fdo/migrations/migrations_owner_onboarding_server_sqlite/*
%{_unitdir}/fdo-serviceinfo-api-server.service
%{_unitdir}/fdo-owner-onboarding-server.service

%post -n fdo-owner-onboarding-server
%systemd_post fdo-owner-onboarding-server.service
%systemd_post fdo-serviceinfo-api-server.service

%preun -n fdo-owner-onboarding-server
%systemd_preun fdo-owner-onboarding-server.service
%systemd_post fdo-serviceinfo-api-server.service

%postun -n fdo-owner-onboarding-server
%systemd_postun_with_restart fdo-owner-onboarding-server.service
%systemd_postun_with_restart fdo-serviceinfo-api-server.service

%package -n fdo-rendezvous-server
Summary: FDO Rendezvous Server implementation
License: %combined_license
%description -n fdo-rendezvous-server
%{summary}

%files -n fdo-rendezvous-server
%license LICENSE LICENSE.dependencies
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%dir %{_sysconfdir}/fdo
%dir %{_sysconfdir}/fdo/keys
%dir %{_sysconfdir}/fdo/rendezvous-server.conf.d
%dir %{_sysconfdir}/fdo/stores
%dir %{_sysconfdir}/fdo/stores/rendezvous_registered
%dir %{_sysconfdir}/fdo/stores/rendezvous_sessions
%{_libexecdir}/fdo/fdo-rendezvous-server
%dir %{_localstatedir}/lib/fdo
%dir %{_docdir}/fdo
%{_docdir}/fdo/rendezvous-*.yml
%{_docdir}/fdo/migrations/migrations_rendezvous_server_postgres/*
%{_docdir}/fdo/migrations/migrations_rendezvous_server_sqlite/*
%{_unitdir}/fdo-rendezvous-server.service

%post -n fdo-rendezvous-server
%systemd_post fdo-rendezvous-server.service

%preun -n fdo-rendezvous-server
%systemd_preun fdo-rendezvous-server.service

%postun -n fdo-rendezvous-server
%systemd_postun_with_restart fdo-rendezvous-server.service

%package -n fdo-manufacturing-server
Summary: FDO Manufacturing Server implementation
License: %combined_license
Requires: openssl-libs >= 3.0.1-12
%description -n fdo-manufacturing-server
%{summary}

%files -n fdo-manufacturing-server
%license LICENSE LICENSE.dependencies
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%dir %{_sysconfdir}/fdo
%dir %{_sysconfdir}/fdo/keys
%dir %{_sysconfdir}/fdo/manufacturing-server.conf.d
%dir %{_sysconfdir}/fdo/stores
%dir %{_sysconfdir}/fdo/stores/manufacturer_keys
%dir %{_sysconfdir}/fdo/stores/manufacturing_sessions
%dir %{_sysconfdir}/fdo/stores/owner_vouchers
%{_libexecdir}/fdo/fdo-manufacturing-server
%dir %{_localstatedir}/lib/fdo
%dir %{_docdir}/fdo
%{_docdir}/fdo/manufacturing-server.yml
%{_docdir}/fdo/migrations/migrations_manufacturing_server_postgres/*
%{_docdir}/fdo/migrations/migrations_manufacturing_server_sqlite/*
%{_unitdir}/fdo-manufacturing-server.service

%post -n fdo-manufacturing-server
%systemd_post fdo-manufacturing-server.service

%preun -n fdo-manufacturing-server
%systemd_preun fdo-manufacturing-server.service

%postun -n fdo-manufacturing-server
%systemd_postun_with_restart fdo-manufacturing-server.service

%package -n fdo-client
Summary: FDO Client implementation
License: %combined_license
Requires: openssl-libs >= 3.0.1-12
Requires: clevis
Requires: clevis-luks
Requires: clevis-pin-tpm2
Requires: cryptsetup
%description -n fdo-client
%{summary}

%files -n fdo-client
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%license LICENSE LICENSE.dependencies
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
License: %combined_license
%description -n fdo-owner-cli
%{summary}

%files -n fdo-owner-cli
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%license LICENSE LICENSE.dependencies
%{_bindir}/fdo-owner-tool
%{_libexecdir}/fdo/fdo-owner-tool

%package -n fdo-admin-cli
Summary: FDO admin tools implementation
License: %combined_license
Requires: fdo-manufacturing-server = %{version}-%{release}
Requires: fdo-rendezvous-server = %{version}-%{release}
Requires: fdo-owner-onboarding-server = %{version}-%{release}
Requires: fdo-owner-cli = %{version}-%{release}
Requires: fdo-client = %{version}-%{release}
Requires: fdo-init = %{version}-%{release}
%description -n fdo-admin-cli
%{summary}

%files -n fdo-admin-cli
%if 0%{?rhel} >= 10
%license cargo-vendor.txt
%endif
%license LICENSE LICENSE.dependencies
%dir %{_sysconfdir}/fdo
%dir %{_sysconfdir}/fdo/keys
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
* Tue Feb 20 2024 Peter Robinson <pbrobinson@fedoraproject.org> - 0.5.0-1
- Update to 0.5.0

* Thu Jan 25 2024 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.13-1
- Update to 0.4.13

* Wed Jul 26 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.12-1
- Update to 0.4.12

* Mon Jul 03 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.11-1
- Update to 0.4.11

* Mon Jul 03 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.10-2
- Updates for eln/c9s building

* Fri Jun 23 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.10-1
- Update to 0.4.10

* Wed Jun 14 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.9-5
- More spec updates

* Wed Jun 14 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.9-4
- Add patch for libcryptsetup-rs 0.8 API changes

* Tue Jun 13 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.9-3
- Updates for licenses

* Tue May 30 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.9-2
- Review feedback
- Patch for libcryptsetup-rs 0.7

* Thu May 11 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.9-1
- Update to 0.4.9

* Mon Feb 20 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.7-3
- Fix services start

* Wed Feb 15 2023 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.7-2
- Upstream fix for rhbz#2168089

* Wed Nov 30 2022 Peter Robinson <pbrobinson@fedoraproject.org> - 0.4.7-1
- Update to 0.4.7
- Package updates and cleanup

* Tue Mar 29 2022 Antonio Murdaca <runcom@linux.com> - 0.4.5-1
- bump to 0.4.5

* Mon Feb 28 2022 Antonio Murdaca <runcom@linux.com> - 0.4.0-2
- fix runtime requirements to use openssl-libs and not -devel

* Thu Feb 24 2022 Antonio Murdaca <runcom@linux.com> - 0.4.0-1
- upgrade to 0.4.0

* Tue Feb 01 2022 Antonio Murdaca <runcom@linux.com> - 0.3.0-1
- bump to 0.3.0

* Tue Jan 11 2022 Antonio Murdaca <runcom@linux.com> - 0.2.0-2
- use patched vendor w/o win files and rename license

* Mon Dec 13 2021 Antonio Murdaca <runcom@linux.com> - 0.2.0-1
- import fido-device-onboard
