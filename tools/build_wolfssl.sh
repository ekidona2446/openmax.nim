#!/usr/bin/env bash
set -euo pipefail

# Build wolfSSL as a shared object for OpenMAX Nim.
#
# Usage from repo root:
#   WOLFSSL_SRC=../wolfssl tools/build_wolfssl.sh
#
# Output:
#   ./libwolfssl.so*          (next to ./openmax)
#   ./lib/libwolfssl.so*      (bundled lib dir fallback)
#
# --enable-opensslextra is intentionally enabled: the Nim ABI uses
# wolfSSL_CTX_set_max_proto_version, which is not exported in the tiny default
# wolfSSL build.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WOLFSSL_SRC="${WOLFSSL_SRC:-${ROOT_DIR}/../wolfssl}"
PREFIX="${WOLFSSL_PREFIX:-${ROOT_DIR}/.wolfssl-install}"

if [[ ! -d "${WOLFSSL_SRC}" ]]; then
  git clone --depth 1 https://github.com/wolfSSL/wolfssl.git "${WOLFSSL_SRC}"
fi

cd "${WOLFSSL_SRC}"
if [[ -x ./autogen.sh ]]; then
  ./autogen.sh
fi
./configure \
  --enable-shared \
  --disable-static \
  --enable-tls13 \
  --enable-opensslextra \
  --prefix="${PREFIX}"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
make install

mkdir -p "${ROOT_DIR}/lib"
cp "${PREFIX}"/lib/libwolfssl.so* "${ROOT_DIR}/lib/"
cp "${PREFIX}"/lib/libwolfssl.so* "${ROOT_DIR}/"

ls -l "${ROOT_DIR}"/libwolfssl.so*
