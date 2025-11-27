#!/bin/bash -

set -eu

VERSION=$(git describe --abbrev=0 --tags)
REVCNT=$(git rev-list --count HEAD)
DEVCNT=$(git rev-list --count $VERSION)
if test $REVCNT != $DEVCNT
then
	VERSION="$VERSION.dev$(expr $REVCNT - $DEVCNT)"
fi
VERSION="1.1.2"
echo "VER: $VERSION"

GITCOMMIT=$(git rev-parse HEAD)
BUILDTIME=$(date -u +%Y/%m/%d-%H:%M:%S)

LDFLAGS="-X main.VERSION=$VERSION -X main.BUILDTIME=$BUILDTIME -X main.GITCOMMIT=$GITCOMMIT"
if [[ -n "${EX_LDFLAGS:-""}" ]]
then
	LDFLAGS="$LDFLAGS $EX_LDFLAGS"
fi

build() {
	echo "$1 $2 ..."
	CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build \
		-ldflags "$LDFLAGS" \
		-o dist/gohttpserver-${3:-""}
}

# Ensure output dir
mkdir -p dist

# If environment variables GOOS/GOARCH are set, prefer them; otherwise detect locally
if [[ -z "${GOOS:-}" || -z "${GOARCH:-}" ]]; then
	UNAME_S=$(uname -s)
	UNAME_M=$(uname -m)

	case "$UNAME_S" in
		Darwin) DETECTED_GOOS=darwin ;;
		Linux) DETECTED_GOOS=linux ;;
		CYGWIN*|MINGW*|MSYS*) DETECTED_GOOS=windows ;;
		*) DETECTED_GOOS=$(echo "$UNAME_S" | tr '[:upper:]' '[:lower:]') ;;
	esac

	case "$UNAME_M" in
		x86_64|amd64) DETECTED_GOARCH=amd64 ;;
		i386|i686) DETECTED_GOARCH=386 ;;
		armv7l|armv7) DETECTED_GOARCH=arm ;;
		aarch64|arm64) DETECTED_GOARCH=arm64 ;;
		*) DETECTED_GOARCH=$UNAME_M ;;
	esac

	GOOS=${GOOS:-$DETECTED_GOOS}
	GOARCH=${GOARCH:-$DETECTED_GOARCH}
fi

# Build a single executable for the detected (or provided) platform
OUT_SUFFIX="${GOOS}-${GOARCH}-$VERSION"
if [[ "$GOOS" == "windows" ]]; then
	# include .exe in the output name for Windows
	build "$GOOS" "$GOARCH" "${OUT_SUFFIX}.exe"
else
	build "$GOOS" "$GOARCH" "$OUT_SUFFIX"
fi

#build darwin arm64 darwin-arm64-$VERSION
#build darwin amd64 darwin-amd64-$VERSION
build linux amd64 linux-amd64-$VERSION
#build linux 386 linux-386-$VERSION
#build linux arm linux-arm-$VERSION
#build windows amd64 win-amd64.exe-$VERSION