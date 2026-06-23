## Minimal wolfSSL ABI used by OpenMAX.
##
## This module intentionally uses dynamic loading (`dynlib`) so the Nim binary can
## be built without a system-wide wolfSSL development package. Runtime TLS needs
## `libwolfssl.so` (Linux), `libwolfssl.dylib` (macOS), or `wolfssl.dll` (Windows)
## built with TLS 1.3 enabled.

import std/os

const
  WolfSslDynLibName* =
    when defined(windows): "wolfssl.dll"
    elif defined(macosx): "libwolfssl.dylib"
    else: "libwolfssl.so"

  WolfSslFiletypePem* = 1.cint

proc wolfSslDynLib*(): string =
  let overridePath = getEnv("OPENMAX_WOLFSSL_LIB")
  if overridePath.len > 0:
    return overridePath

  let appDir = getAppDir()
  let besideBinary = appDir / WolfSslDynLibName
  if fileExists(besideBinary):
    return besideBinary

  let bundledLibDir = appDir / "lib" / WolfSslDynLibName
  if fileExists(bundledLibDir):
    return bundledLibDir

  WolfSslDynLibName

const
  ## Return values expected from custom IO callbacks.
  WolfSslCbioErrWantRead* = -2.cint
  WolfSslCbioErrWantWrite* = -2.cint
  WolfSslCbioErrGeneral* = -1.cint

  ## wolfSSL_get_error values. They match the OpenSSL-compatible WANT codes.
  WolfSslErrorWantRead* = 2.cint
  WolfSslErrorWantWrite* = 3.cint
  WolfSslErrorZeroReturn* = 6.cint

  ## wolfSSL protocol version enum value.
  WolfSslTlsV12* = 3.cint
  WolfSslTlsV13* = 4.cint

  ## OpenSSL compatibility protocol version values.
  OsslTlsV12* = 0x0303.cint
  OsslTlsV13* = 0x0304.cint

type
  WolfSslCtx* = object
  WolfSslMethod* = object
  WolfSsl* = object

  WolfSslCtxPtr* = ptr WolfSslCtx
  WolfSslMethodPtr* = ptr WolfSslMethod
  WolfSslPtr* = ptr WolfSsl

  WolfSslIoRecvCb* = proc(ssl: WolfSslPtr, buf: pointer, sz: cint, ctx: pointer): cint {.cdecl, gcsafe, raises: [].}
  WolfSslIoSendCb* = proc(ssl: WolfSslPtr, buf: pointer, sz: cint, ctx: pointer): cint {.cdecl, gcsafe, raises: [].}

proc wolfSSL_Init*(): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_Cleanup*(): cint {.importc, dynlib: wolfSslDynLib().}

proc wolfTLSv1_3_server_method*(): WolfSslMethodPtr {.importc, dynlib: wolfSslDynLib().}
proc wolfTLS_server_method*(): WolfSslMethodPtr {.importc, dynlib: wolfSslDynLib().}

proc wolfSSL_CTX_new*(tlsMethod: WolfSslMethodPtr): WolfSslCtxPtr {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_free*(ctx: WolfSslCtxPtr) {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_SetMinVersion*(ctx: WolfSslCtxPtr, version: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_set_max_proto_version*(ctx: WolfSslCtxPtr, version: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_use_certificate_file*(ctx: WolfSslCtxPtr, file: cstring, filetype: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_use_PrivateKey_file*(ctx: WolfSslCtxPtr, file: cstring, filetype: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_SetIORecv*(ctx: WolfSslCtxPtr, cb: WolfSslIoRecvCb) {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_CTX_SetIOSend*(ctx: WolfSslCtxPtr, cb: WolfSslIoSendCb) {.importc, dynlib: wolfSslDynLib().}

proc wolfSSL_new*(ctx: WolfSslCtxPtr): WolfSslPtr {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_free*(ssl: WolfSslPtr) {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_dtls_set_using_nonblock*(ssl: WolfSslPtr, nonblock: cint) {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_SetIOReadCtx*(ssl: WolfSslPtr, ctx: pointer) {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_SetIOWriteCtx*(ssl: WolfSslPtr, ctx: pointer) {.importc, dynlib: wolfSslDynLib().}

proc wolfSSL_accept*(ssl: WolfSslPtr): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_read*(ssl: WolfSslPtr, buf: pointer, sz: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_write*(ssl: WolfSslPtr, buf: pointer, sz: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_get_error*(ssl: WolfSslPtr, ret: cint): cint {.importc, dynlib: wolfSslDynLib().}
proc wolfSSL_get_version*(ssl: WolfSslPtr): cstring {.importc, dynlib: wolfSslDynLib().}
