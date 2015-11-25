Format:         1.0
Source:         alert-agent
Version:        0.1.0-1
Binary:         alert-agent
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
    libcxxtools-dev,
    dh-autoreconf

Package-List:
 alert-agent dev net optional arch-any

