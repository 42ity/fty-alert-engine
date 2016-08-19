#
#    alert-agent - Evaluates rules written in Lua and produce alerts
#
#    Copyright (C) 2014 - 2015 Eaton
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

Name:           alert-agent
Version:        0.1.0
Release:        1
Summary:        evaluates rules written in lua and produce alerts
License:        GPL-2.0+
URL:            https://eaton.com/
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkg-config
BuildRequires:  systemd-devel
BuildRequires:  gcc-c++
BuildRequires:  libsodium-devel
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  libbiosproto-devel
BuildRequires:  lua-devel
BuildRequires:  cxxtools-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
alert-agent evaluates rules written in lua and produce alerts.

%package -n libalert_agent0
Group:          System/Libraries
Summary:        evaluates rules written in lua and produce alerts

%description -n libalert_agent0
alert-agent evaluates rules written in lua and produce alerts.
This package contains shared library.

%post -n libalert_agent0 -p /sbin/ldconfig
%postun -n libalert_agent0 -p /sbin/ldconfig

%files -n libalert_agent0
%defattr(-,root,root)
%doc COPYING
%{_libdir}/libalert_agent.so.*

%package devel
Summary:        evaluates rules written in lua and produce alerts
Group:          System/Libraries
Requires:       libalert_agent0 = %{version}
Requires:       libsodium-devel
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       libbiosproto-devel
Requires:       lua-devel
Requires:       cxxtools-devel

%description devel
alert-agent evaluates rules written in lua and produce alerts.
This package contains development files.

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libalert_agent.so
%{_libdir}/pkgconfig/libalert_agent.pc

%prep
%setup -q

%build
sh autogen.sh
%{configure} --with-systemd
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc COPYING
%{_bindir}/bios-agent-alert-generator
%{_prefix}/lib/systemd/system/bios-agent-alert-generator*.service

%dir /var/lib/bios/alert_agent
/var/lib/bios/alert_agent/warranty.rule
%dir /usr/lib/tmpfiles.d
/usr/lib/tmpfiles.d/bios-agent-alert-generator.conf

%changelog
