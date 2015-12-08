Format:         1.0
Source:         alert-agent
Version:        0.1.0-1
Binary:         libalert-agent0, alert-agent-dev
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
 libalert-agent0 deb net optional arch=any
 alert-agent-dev deb libdevel optional arch=any

