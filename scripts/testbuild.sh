#!/usr/bin/env bash

GO=go
PKG_NAME=myrasec
VERSION=$(git describe --tags --always)
TEST_BUILD_OS=(freebsd windows linux)
TEST_BUILD_ARCHS=(amd64 '386' arm arm64)

rm -rf testbuild-terraform-provider-${PKG_NAME}_*

for OS in ${TEST_BUILD_OS[@]}; do
	for ARCH in ${TEST_BUILD_ARCHS[@]};	do
        echo "Building ${OS}/${ARCH}: testbuild-terraform-provider-${PKG_NAME}_${VERSION}_${OS}_${ARCH}"
		env GOOS=${OS} GOARCH=${ARCH} ${GO} build -o testbuild-terraform-provider-${PKG_NAME}_${VERSION}_${OS}_${ARCH}
	done
done


# testing build for "special" darwin
echo "Building darwin/amd64: terraform-provider-${PKG_NAME}_${VERSION}_darwin_amd64"
env GOOS=darwin GOARCH=amd64 ${GO} build -o testbuild-terraform-provider-${PKG_NAME}_${VERSION}_darwin_amd64
echo "Building darwin/arm64: terraform-provider-${PKG_NAME}_${VERSION}_darwin_arm64"
env GOOS=darwin GOARCH=arm64 ${GO} build -o testbuild-terraform-provider-${PKG_NAME}_${VERSION}_darwin_arm64

rm -rf testbuild-terraform-provider-${PKG_NAME}_*