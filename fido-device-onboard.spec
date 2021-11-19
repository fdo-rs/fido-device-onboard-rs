%define dracutlibdir %{_prefix}/lib/dracut
%bcond_without check
%global __cargo_skip_build 0
%global __cargo_is_lib() false
%global forgeurl https://github.com/fedora-iot/fido-device-onboard-rs

%forgemeta

Name:           fido-device-onboard
Version:        0.1.0
Release:        1%{?dist}
Summary:        An implementation of the FIDO Device Onboard Specification written in rust

License:        BSD 3
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
BuildRequires: openssl-devel

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

%install
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-client-linuxapp
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-client
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-onboarding-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-rendezvous-server
install -D -m 0755 -t %{buildroot}%{_bindir} target/release/fdo-owner-tool
install -D -m 0644 -t %{buildroot}%{_unitdir} examples/systemd/*
install -D -m 0644 -t %{buildroot}%{_docdir}/fdo examples/config/*
# 52fdo
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/module-setup.sh
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-generator
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-service
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client.service

%package -n fdo-init
Summary: dracut module for device initialization
%description -n fdo-init
%{summary}

%files -n fdo-init
%license LICENSE
%{dracutlibdir}/modules.d/52fdo/*
%{_libexecdir}/fdo/fdo-manufacturing-client

%package -n fdo-owner-onboarding-server
Summary: FDO Owner Onboarding Server implementation
%description -n fdo-owner-onboarding-server
%{summary}

%files -n fdo-owner-onboarding-server
%license LICENSE
%{_libexecdir}/fdo/fdo-owner-onboarding-server
%{_docdir}/fdo/owner-onboarding-server.yml
%{_unitdir}/fdo-owner-onboarding-server.service

%post -n fdo-owner-onboarding-server
%systemd_post fdo-owner-onboarding-server.service

%preun -n fdo-owner-onboarding-server
%systemd_preun fdo-owner-onboarding-server.service

%postun -n fdo-owner-onboarding-server
%systemd_postun_with_restart fdo-owner-onboarding-server.service

%package -n fdo-rendezvous-server
Summary: FDO Rendezvous Server implementation
%description -n fdo-rendezvous-server
%{summary}

%files -n fdo-rendezvous-server
%license LICENSE
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
%description -n fdo-manufacturing-server
%{summary}

%files -n fdo-manufacturing-server
%license LICENSE
%{_libexecdir}/fdo/fdo-manufacturing-server
%{_docdir}/fdo/manufacturing-server.yml
%{_docdir}/fdo/rendezvous-info.yml
%{_unitdir}/fdo-manufacturing-server.service

%post -n fdo-manufacturing-server
%systemd_post fdo-manufacturing-server.service

%preun -n fdo-manufacturing-server
%systemd_preun fdo-manufacturing-server.service

%postun -n fdo-manufacturing-server
%systemd_postun_with_restart fdo-manufacturing-server.service

%package -n fdo-client
Summary: FDO Client implementation
%description -n fdo-client
%{summary}

%files -n fdo-client
%license LICENSE
%{_libexecdir}/fdo/fdo-client-linuxapp
%{_unitdir}/fdo-client-linuxapp.service

%post -n fdo-client
%systemd_post fdo-client-linuxapp.service

%preun -n fdo-client
%systemd_preun fdo-client-linuxapp.service

%postun -n fdo-client
%systemd_postun_with_restart fdo-client.linuxapp.service

%package -n fdo-owner-cli
Summary: FDO Owner tools implementation
%description -n fdo-owner-cli
%{summary}

%files -n fdo-owner-cli
%license LICENSE
%{_bindir}/fdo-owner-tool
%{_docdir}/fdo/owner-addresses.yml

%changelog
* Tue Oct 5 2021 Antonio Murdaca <amurdaca@redhat.com> - 0.1.0-1
- initial release