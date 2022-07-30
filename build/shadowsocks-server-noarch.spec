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
mkdir -p %{buildroot}/opt/shadowsocks-server/shadowsocks
mkdir -p %{buildroot}/opt/shadowsocks-server/shadowsocks/crypto
mkdir -p %{buildroot}/opt/shadowsocks-server/shadowsocks/obfsplugin
mkdir -p %{buildroot}/opt/shadowsocks-server/utils
mkdir -p %{buildroot}/opt/shadowsocks-server/utils/fail2ban
mkdir -p %{buildroot}%{_unitdir}
install -m 755 %{_builddir}/%{name}-%{version}/* %{buildroot}/opt/shadowsocks-server
install -m 755 %{_builddir}/%{name}-%{version}/shadowsocks/* %{buildroot}/opt/shadowsocks-server/shadowsocks
install -m 755 %{_builddir}/%{name}-%{version}/shadowsocks/crypto/* %{buildroot}/opt/shadowsocks-server/shadowsocks/crypto
install -m 755 %{_builddir}/%{name}-%{version}/shadowsocks/obfsplugin/* %{buildroot}/opt/shadowsocks-server/shadowsocks/obfsplugin
install -m 755 %{_builddir}/%{name}-%{version}/utils/* %{buildroot}/opt/shadowsocks-server/utils
install -m 755 %{_builddir}/%{name}-%{version}/utils/fail2ban/* %{buildroot}/opt/shadowsocks-server/utils/fail2ban
install -m 644 %{_builddir}/shadowsocks-server.service %{buildroot}%{_unitdir}

%clean
rm -rf %{buildroot}

%files
/opt/shadowsocks-server/*
/opt/shadowsocks-server/shadowsocks/*
/opt/shadowsocks-server/shadowsocks/crypto/*
/opt/shadowsocks-server/shadowsocks/obfsplugin/*
/opt/shadowsocks-server/utils/*
/opt/shadowsocks-server/utils/fail2ban/*
%{_unitdir}/shadowsocks-server.service
