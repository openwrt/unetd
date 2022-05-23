#!/bin/bash

build() (
	local dir="$1"; shift
	cd "$dir"
	cmake -DCMAKE_INSTALL_PREFIX=$PWD/../install "$@" .
	make -j9
	make install
)

clone() (
	local dir="$1"
	local url="$2"
	if [ -d "$dir" ]; then 
		cd "$dir"
		git pull --rebase
	else
		git clone "$url" "$dir"
	fi
)

UNAME="$(uname)"
set -e -x
rm -rf install
clone libubox git://git.openwrt.org/project/libubox.git
build libubox -DBUILD_LUA=off
if [ "$UNAME" = "Linux" ]; then
	clone libnl-tiny git://git.openwrt.org/project/libnl-tiny.git
	build libnl-tiny -DBUILD_LUA=off
fi
rm -f install/lib/*.{so,dylib}
if [ "$UNAME" = "Linux" ]; then
	mv install/include/libnl-tiny/* install/include/
fi
export CFLAGS=-I$PWD/install/include
export LDFLAGS=-L$PWD/install/lib
cmake -DCMAKE_FIND_ROOT_PATH=$PWD/install -DUBUS_SUPPORT=off .
make -j9
