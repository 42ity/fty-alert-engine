Format:         1.0
Source:         alert_generator
Version:        0.1.0-1
Binary:         alert_generator
Architecture:   any all
Maintainer:     John Doe <John.Doe@example.com>
Standards-Version: 3.9.5
Build-Depends: bison, debhelper (>= 8),
    pkg-config,
    automake,
    autoconf,
    libtool,
    libzmq4-dev,
    libczmq-dev,
    libmlm-dev,
    libbiosproto-dev,
    liblua5.1-0-dev,
    dh-autoreconf

Package-List:
 alert_generator dev net optional arch-any

