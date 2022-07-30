Name:           shadowsocks-server
Version:        0.0.1
Release:        1%{?dist}
Summary:        Shadowsocks Server for SSPanel-UIM.
Group:          Unspecified
License:        Apache-2.0
URL:            https://github.com/Anankke/shadowsocks-mod
Packager:       SSPanel-UIM Team <package@sspanel.org>
BuildArch:      noarch
BuildRequires:  systemd
Requires:       python3-requests, python3-setuptools

%description
A Shadowsocks implementation from SSPanel-UIM.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/shadowsocks-server
mkdir -p %{buildroot}%{_unitdir}
install -m 755 %{_builddir}/%{name}-%{version}/* %{buildroot}/opt/shadowsocks-server
install -m 644 %{_builddir}/shadowsocks-server.service %{buildroot}%{_unitdir}

%clean
rm -rf %{buildroot}

%files
/opt/shadowsocks-server/*
%{_unitdir}/shadowsocks-server.service
