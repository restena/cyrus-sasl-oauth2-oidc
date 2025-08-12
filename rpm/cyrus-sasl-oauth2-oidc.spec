Name:           cyrus-sasl-oauth2-oidc
Version:        1.0.0
Release:        1%{?dist}
Summary:        OAuth2/OIDC SASL plugin for Cyrus SASL

License:        MIT
URL:            https://github.com/stefb/cyrus-sasl-oauth2-oidc
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  cyrus-sasl-devel
BuildRequires:  liboauth2-devel
BuildRequires:  cjose-devel
BuildRequires:  jansson-devel
BuildRequires:  libcurl-devel
BuildRequires:  openssl-devel

Requires:       cyrus-sasl
Requires:       liboauth2
Requires:       cjose
Requires:       jansson
Requires:       libcurl
Requires:       openssl-libs

%description
This package provides an OAuth2/OIDC authentication mechanism plugin
for Cyrus SASL. It allows applications using SASL to authenticate
users via OAuth2/OpenID Connect providers.

The plugin supports various OAuth2 flows and integrates seamlessly
with existing SASL-enabled applications like mail servers, LDAP
servers, and other network services.

%prep
%autosetup

%build
autoreconf -fiv
%configure --disable-tests
%make_build

%install
%make_install

%files
%license LICENSE
%doc README.md
%{_libdir}/sasl2/liboauth2.so*
%{_libdir}/sasl2/liboauth2.a
%{_libdir}/sasl2/liboauthbearer.so*
%{_libdir}/sasl2/libxoauth2.so*

%post
/sbin/ldconfig
if systemctl is-active --quiet saslauthd; then
    systemctl restart saslauthd || :
fi

%postun
/sbin/ldconfig
if [ $1 -eq 0 ] && systemctl is-active --quiet saslauthd; then
    systemctl restart saslauthd || :
fi

%changelog
* Mon Aug 12 2024 Stephane Benoit <stephane.benoit@example.com> - 1.0.0-1
- Initial RPM package for cyrus-sasl-oauth2-oidc
- OAuth2/OIDC SASL authentication plugin
- Support for Fedora and RHEL/CentOS via EPEL
