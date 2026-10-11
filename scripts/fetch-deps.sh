#!/bin/sh
# deploy deps through the LKM-SDK at the pinned rev
# .sdk-version pins the SDK, cloned once into .sdk/ (gitignored)
# a rev that is not a commit id falls back to the SDK default branch
set -e

cd "$(dirname "$0")/.."

SDKREV=$(cat .sdk-version)

if [ ! -d .sdk/.git ]; then
	rm -rf .sdk
	git clone https://github.com/Dere3046/KMSDK.git .sdk
fi

case $SDKREV in
[0-9a-f]*)
	git -C .sdk fetch origin 2>/dev/null || true
	git -C .sdk checkout "$SDKREV"
	;;
*)
	# anything but a commit id follows the default branch
	git -C .sdk fetch origin
	git -C .sdk checkout -q FETCH_HEAD
	;;
esac

# 使用自己的 HooKern Fork
if [ -n "${HOO_FORK_URL:-}" ]; then
    HOO_REV=$(awk '$1=="HooKern" {print $2; exit}' deps.lst)
    [ -n "$HOO_REV" ] || {
        echo "ERROR: HooKern revision missing"
        exit 1
    }

    mkdir -p deps

    if [ ! -d deps/HooKern/.git ]; then
        git clone "$HOO_FORK_URL" deps/HooKern
    fi

    ACTUAL_URL=$(git -C deps/HooKern remote get-url origin)
    [ "$ACTUAL_URL" = "$HOO_FORK_URL" ] || {
        echo "ERROR: wrong HooKern remote: $ACTUAL_URL"
        exit 1
    }

    git -C deps/HooKern fetch origin
    git -C deps/HooKern checkout --detach "$HOO_REV"

    echo "HooKern revision:"
    git -C deps/HooKern rev-parse HEAD
fi

exec .sdk/scripts/sdk install
