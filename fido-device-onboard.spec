%define dracutlibdir %{_prefix}/lib/dracut
%bcond_without check
%global __cargo_skip_build 0
%global __cargo_is_lib() false
%global forgeurl https://github.com/fedora-iot/fido-device-onboard-rs
%global rpmdocsdir docs-rpms

Version:        0.4.6

%forgemeta

Name:           fido-device-onboard
Release:        1%{?dist}
Summary:        An implementation of the FIDO Device Onboard Specification written in rust

License:        BSD
URL:            %{forgeurl}
Source:         %{forgesource}
%if 0%{?rhel} && !0%{?eln}
%if "%{?commit}" != ""
Source1:        %{name}-rs-%{commit}-vendor.tar.gz
%else
Source1:        %{name}-rs-%{version}-vendor.tar.gz
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

%description
%{summary}.

%prep
%forgesetup
%if 0%{?rhel} && !0%{?eln}
%cargo_prep -V 1
%else
%cargo_prep
%endif

%build
%cargo_build
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
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo examples/config/*
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
%{_docdir}/fdo/owner-onboarding-server.yml
%{_docdir}/fdo/serviceinfo-api-server.yml
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
%{_docdir}/fdo/rendezvous-server.yml
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
%{_docdir}/fdo/manufacturing-server.yml
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
