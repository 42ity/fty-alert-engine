#
#    alert-generator - Evaluates rules written in Lua and produce alerts
#
#    Copyright (c) the Authors
#

Name:           alert-generator
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
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  biosproto-devel
BuildRequires:  lua-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
alert-generator evaluates rules written in lua and produce alerts.


%prep
%setup -q

%build
sh autogen.sh
%{configure}
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc README.md COPYING
%{_bindir}/alert-agent
%config(noreplace) %{_systemconfdir}/alert-generator/alert-agent.cfg
%{_prefix}/lib/systemd/system/alert-agent.service

%changelog
