#
#    fty-alert-engine - 42ity service evaluating rules written in Lua and producing alerts
#
#    Copyright (C) 2019 - 2019 Eaton
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
%define SYSTEMD_UNIT_DIR %(pkg-config --variable=systemdsystemunitdir systemd)
Name:           fty-alert-engine
Version:        1.0.0
Release:        1
Summary:        42ity service evaluating rules written in lua and producing alerts
License:        GPL-2.0+
URL:            https://42ity.org
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
# Note: ghostscript is required by graphviz which is required by
#       asciidoc. On Fedora 24 the ghostscript dependencies cannot
#       be resolved automatically. Thus add working dependency here!
BuildRequires:  ghostscript
BuildRequires:  asciidoc
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  systemd-devel
BuildRequires:  systemd
%{?systemd_requires}
BuildRequires:  xmlto
BuildRequires:  gcc-c++
BuildRequires:  libsodium-devel
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  log4cplus-devel
BuildRequires:  fty-common-logging-devel
BuildRequires:  fty-proto-devel
BuildRequires:  lua-devel
BuildRequires:  cxxtools-devel
BuildRequires:  fty-common-devel
BuildRequires:  openssl-devel
BuildRequires:  fty-common-mlm-devel
BuildRequires:  fty_shm-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
fty-alert-engine 42ity service evaluating rules written in lua and producing alerts.

%package -n libfty_alert_engine0
Group:          System/Libraries
Summary:        42ity service evaluating rules written in lua and producing alerts shared library

%description -n libfty_alert_engine0
This package contains shared library for fty-alert-engine: 42ity service evaluating rules written in lua and producing alerts

%post -n libfty_alert_engine0 -p /sbin/ldconfig
%postun -n libfty_alert_engine0 -p /sbin/ldconfig

%files -n libfty_alert_engine0
%defattr(-,root,root)
%{_libdir}/libfty_alert_engine.so.*

%package devel
Summary:        42ity service evaluating rules written in lua and producing alerts
Group:          System/Libraries
Requires:       libfty_alert_engine0 = %{version}
Requires:       libsodium-devel
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       log4cplus-devel
Requires:       fty-common-logging-devel
Requires:       fty-proto-devel
Requires:       lua-devel
Requires:       cxxtools-devel
Requires:       fty-common-devel
Requires:       openssl-devel
Requires:       fty-common-mlm-devel
Requires:       fty_shm-devel

%description devel
42ity service evaluating rules written in lua and producing alerts development tools
This package contains development files for fty-alert-engine: 42ity service evaluating rules written in lua and producing alerts

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libfty_alert_engine.so
%{_libdir}/pkgconfig/libfty_alert_engine.pc
%{_mandir}/man3/*
%{_mandir}/man7/*

%prep

%setup -q

%build
sh autogen.sh
%{configure} --enable-drafts=%{DRAFTS} --with-systemd-units
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc README.md
%{_bindir}/fty-alert-engine
%{_mandir}/man1/fty-alert-engine*
%config(noreplace) %{_sysconfdir}/fty-alert-engine/fty-alert-engine.cfg
%{SYSTEMD_UNIT_DIR}/fty-alert-engine.service
%dir %{_sysconfdir}/fty-alert-engine
%if 0%{?suse_version} > 1315
%post
%systemd_post fty-alert-engine.service
%preun
%systemd_preun fty-alert-engine.service
%postun
%systemd_postun_with_restart fty-alert-engine.service
%endif

%changelog
