#!/bin/bash

_exists() {
    command -v "$1" > /dev/null
}

_try_install() {
    echo "Could not find protoc plugin $1. Install it? (y/n)" 1>&2
    echo " $ go install $2"
    while read -r answer; do
        case "$answer" in
            y|Y)
                go install "$2"
                # Make sure the new executable is in path
                export PATH="$PATH:${GOPATH:-$HOME/go}/bin"
                break
                ;;
            n|N)
                exit 1
                ;;
            *)
                echo "Invalid input. 'y' or 'n' expected"
                ;;
        esac
    done
    unset answer
}


set -e
cd "$(dirname "$0")"

if ! _exists protoc; then
    echo "Could not find a protobuf compiler (protoc)." 1>&2
    # Do not try to install protoc as that is usually handled by the package manager
    exit 127
fi

if ! _exists protoc-gen-go; then
    _try_install protoc-gen-go "google.golang.org/protobuf/cmd/protoc-gen-go@latest" || exit 127
fi


if ! _exists protoc-gen-go-grpc; then
    _try_install protoc-gen-go-grpc "google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" || exit 127
fi

protoc -I=../src/main/proto --go_out=. --go-grpc_out=. ../src/main/proto/snp-attestd-service.proto
