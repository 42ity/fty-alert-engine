#!/usr/bin/env bash
set -e

# Set this to enable verbose profiling
[ -n "${CI_TIME-}" ] || CI_TIME=""
case "$CI_TIME" in
    [Yy][Ee][Ss]|[Oo][Nn]|[Tt][Rr][Uu][Ee])
        CI_TIME="time -p " ;;
    [Nn][Oo]|[Oo][Ff][Ff]|[Ff][Aa][Ll][Ss][Ee])
        CI_TIME="" ;;
esac

# Set this to enable verbose tracing
[ -n "${CI_TRACE-}" ] || CI_TRACE="no"
case "$CI_TRACE" in
    [Nn][Oo]|[Oo][Ff][Ff]|[Ff][Aa][Ll][Ss][Ee])
        set +x ;;
    [Yy][Ee][Ss]|[Oo][Nn]|[Tt][Rr][Uu][Ee])
        set -x ;;
esac

LANG=C
LC_ALL=C
export LANG LC_ALL

if [ -d "./tmp" ]; then
    # Proto installation area for this project and its deps
    rm -rf ./tmp
fi
if [ -d "./tmp-deps" ]; then
    # Checkout/unpack and build area for dependencies
    rm -rf ./tmp-deps
fi
mkdir -p tmp tmp-deps
BUILD_PREFIX=$PWD/tmp

# Use tools from prerequisites we might have built
PATH="${BUILD_PREFIX}/sbin:${BUILD_PREFIX}/bin:${PATH}"
export PATH

CONFIG_OPTS=()
CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")
CONFIG_OPTS+=("--with-docs=no")
if [ -z "${CI_CONFIG_QUIET-}" ] || [ "${CI_CONFIG_QUIET-}" = yes ] || [ "${CI_CONFIG_QUIET-}" = true ]; then
    CONFIG_OPTS+=("--quiet")
fi

CMAKE_OPTS=()
CMAKE_OPTS+=("-DCMAKE_INSTALL_PREFIX:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_PREFIX_PATH:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_LIBRARY_PATH:PATH=${BUILD_PREFIX}/lib")
CMAKE_OPTS+=("-DCMAKE_INCLUDE_PATH:PATH=${BUILD_PREFIX}/include")

if [ "$CLANG_FORMAT" != "" ] ; then
    CMAKE_OPTS+=("-DCLANG_FORMAT=${CLANG_FORMAT}")
fi

# Clone and build dependencies
[ -z "$CI_TIME" ] || echo "`date`: Starting build of dependencies (if any)..."
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b 1.0.5-FTY-master https://github.com/42ity/libsodium.git libsodium
    cd libsodium
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libzmq3-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions libzmq >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b 4.2.0-FTY-master https://github.com/42ity/libzmq.git libzmq
    cd libzmq
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libczmq-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions czmq >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b v3.0.2-FTY-master https://github.com/42ity/czmq.git czmq
    cd czmq
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libmlm-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions malamute >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b 1.0-FTY-master https://github.com/42ity/malamute.git malamute
    cd malamute
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list log4cplus-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions log4cplus >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b 1.1.2-FTY-master https://github.com/42ity/log4cplus.git log4cplus
    cd log4cplus
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_common_logging-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-common-logging >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-common-logging.git fty-common-logging
    cd fty-common-logging
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_proto-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-proto >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-proto.git fty-proto
    cd fty-proto
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list cxxtools-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions cxxtools >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b 2.2-FTY-master https://github.com/42ity/cxxtools.git cxxtools
    cd cxxtools
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_common-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-common >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-common.git fty-common
    cd fty-common
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_shm-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty_shm >/dev/null 2>&1)); then
    BASE_PWD=${PWD}
    cd tmp-deps
    $CI_TIME git clone --quiet --depth 1 https://github.com/42ity/fty-shm.git fty_shm
    cd fty_shm
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
    git --no-pager log --oneline -n1
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi

cd ../..

# always install custom builds from dist if the autotools chain exists
# to make sure that `make dist` doesn't omit any files required to build & test
if [ -z "$DO_CLANG_FORMAT_CHECK" -a -f configure.ac ]; then
    $CI_TIME ./autogen.sh
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j5 dist-gzip
    $CI_TIME tar -xzf fty-alert-engine-1.0.0.tar.gz
    cd fty-alert-engine-1.0.0
fi

# Build and check this project
[ -z "$CI_TIME" ] || echo "`date`: Starting build of currently tested project..."
CCACHE_BASEDIR=${PWD}
export CCACHE_BASEDIR
if [ "$DO_CLANG_FORMAT_CHECK" = "1" ] ; then
    { PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig $CI_TIME cmake "${CMAKE_OPTS[@]}" . \
      && make clang-format-check-CI ; exit $? ; }
else
    PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig $CI_TIME cmake "${CMAKE_OPTS[@]}" .
    $CI_TIME make all VERBOSE=1 -j4
    $CI_TIME ctest -V
    $CI_TIME make install
fi
[ -z "$CI_TIME" ] || echo "`date`: Builds completed without fatal errors!"

echo "=== Are GitIgnores good after making the project '$BUILD_TYPE'? (should have no output below)"
git status -s || true
echo "==="
