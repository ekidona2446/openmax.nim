import std/[os]
import chronos
import ./wolfssl_abi

export wolfssl_abi

type
  WolfTlsError* = object of CatchableError
  WolfTlsClosedError* = object of WolfTlsError

  WolfTlsContext* = ref object
    ctx*: WolfSslCtxPtr

  WolfTlsSession* = ref object
    ctx*: WolfTlsContext
    ssl*: WolfSslPtr
    inBuf*: seq[byte]
    inPos*: int
    outBuf*: seq[byte]
    closed*: bool

  WolfTlsConnection* = ref object
    raw*: StreamTransport
    session*: WolfTlsSession
    handshakeDone*: bool

const
  WolfEncryptedReadChunk* = 16 * 1024

proc raiseWolf(message: string) {.noreturn.} =
  raise newException(WolfTlsError, message)

proc consumeInput(s: WolfTlsSession, dst: pointer, size: int): int {.gcsafe, raises: [].} =
  if s.inPos >= s.inBuf.len:
    s.inBuf.setLen(0)
    s.inPos = 0
    return 0
  let n = min(size, s.inBuf.len - s.inPos)
  if n > 0:
    copyMem(dst, unsafeAddr s.inBuf[s.inPos], n)
    s.inPos += n
    if s.inPos >= s.inBuf.len:
      s.inBuf.setLen(0)
      s.inPos = 0
  n

proc appendOutput(s: WolfTlsSession, src: pointer, size: int): int {.gcsafe, raises: [].} =
  if size <= 0:
    return 0
  let oldLen = s.outBuf.len
  s.outBuf.setLen(oldLen + size)
  copyMem(addr s.outBuf[oldLen], src, size)
  size

proc wolfRecvCb(ssl: WolfSslPtr, buf: pointer, sz: cint, ctx: pointer): cint {.cdecl, gcsafe, raises: [].} =
  let session = cast[WolfTlsSession](ctx)
  if session.isNil or session.closed:
    return WolfSslCbioErrGeneral
  let n = session.consumeInput(buf, int(sz))
  if n == 0: WolfSslCbioErrWantRead else: cint(n)

proc wolfSendCb(ssl: WolfSslPtr, buf: pointer, sz: cint, ctx: pointer): cint {.cdecl, gcsafe, raises: [].} =
  let session = cast[WolfTlsSession](ctx)
  if session.isNil or session.closed:
    return WolfSslCbioErrGeneral
  cint(session.appendOutput(buf, int(sz)))

proc parseTlsVersion(v: string, def: cint): cint =
  if v == "1.2": return WolfSslTlsV12
  if v == "1.3": return WolfSslTlsV13
  return def

proc parseOsslTlsVersion(v: string, def: cint): cint =
  if v == "1.2": return OsslTlsV12
  if v == "1.3": return OsslTlsV13
  return def

proc newWolfTlsContext*(certFile, keyFile, minVer, maxVer: string): WolfTlsContext =
  if not fileExists(certFile):
    raiseWolf("wolfSSL certificate file not found: " & certFile)
  if not fileExists(keyFile):
    raiseWolf("wolfSSL private key file not found: " & keyFile)

  if wolfSSL_Init() != 1:
    raiseWolf("wolfSSL_Init failed")

  let tlsMethod = wolfTLS_server_method()
  if tlsMethod.isNil:
    raiseWolf("wolfTLS_server_method returned nil; is wolfSSL built correctly?")

  let rawCtx = wolfSSL_CTX_new(tlsMethod)
  if rawCtx.isNil:
    raiseWolf("wolfSSL_CTX_new failed")

  let cMinVer = parseTlsVersion(minVer, WolfSslTlsV12)
  if wolfSSL_CTX_SetMinVersion(rawCtx, cMinVer) != 1:
    wolfSSL_CTX_free(rawCtx)
    raiseWolf("wolfSSL_CTX_SetMinVersion failed")

  let cMaxVer = parseOsslTlsVersion(maxVer, OsslTlsV13)
  if wolfSSL_CTX_set_max_proto_version(rawCtx, cMaxVer) != 1:
    wolfSSL_CTX_free(rawCtx)
    raiseWolf("wolfSSL_CTX_set_max_proto_version failed")

  if wolfSSL_CTX_use_certificate_file(rawCtx, certFile.cstring, WolfSslFiletypePem) != 1:
    wolfSSL_CTX_free(rawCtx)
    raiseWolf("wolfSSL_CTX_use_certificate_file failed: " & certFile)

  if wolfSSL_CTX_use_PrivateKey_file(rawCtx, keyFile.cstring, WolfSslFiletypePem) != 1:
    wolfSSL_CTX_free(rawCtx)
    raiseWolf("wolfSSL_CTX_use_PrivateKey_file failed: " & keyFile)

  wolfSSL_CTX_SetIORecv(rawCtx, wolfRecvCb)
  wolfSSL_CTX_SetIOSend(rawCtx, wolfSendCb)

  WolfTlsContext(ctx: rawCtx)

proc close*(ctx: WolfTlsContext) =
  if not ctx.isNil and not ctx.ctx.isNil:
    wolfSSL_CTX_free(ctx.ctx)
    ctx.ctx = nil

proc newWolfTlsSession*(ctx: WolfTlsContext): WolfTlsSession =
  if ctx.isNil or ctx.ctx.isNil:
    raiseWolf("wolfSSL context is nil")
  result = WolfTlsSession(ctx: ctx, inBuf: @[], outBuf: @[])
  result.ssl = wolfSSL_new(ctx.ctx)
  if result.ssl.isNil:
    raiseWolf("wolfSSL_new failed")
  GC_ref(result)
  wolfSSL_dtls_set_using_nonblock(result.ssl, 1)
  wolfSSL_SetIOReadCtx(result.ssl, cast[pointer](result))
  wolfSSL_SetIOWriteCtx(result.ssl, cast[pointer](result))

proc close*(s: WolfTlsSession) =
  if s.isNil or s.closed:
    return
  s.closed = true
  if not s.ssl.isNil:
    wolfSSL_free(s.ssl)
    s.ssl = nil
  GC_unref(s)

proc newWolfTlsConnection*(raw: StreamTransport, ctx: WolfTlsContext): WolfTlsConnection =
  WolfTlsConnection(raw: raw, session: newWolfTlsSession(ctx), handshakeDone: false)

proc feed*(s: WolfTlsSession, data: openArray[byte]) =
  if data.len == 0:
    return
  if s.inPos > 0:
    s.inBuf = s.inBuf[s.inPos .. ^1]
    s.inPos = 0
  let oldLen = s.inBuf.len
  s.inBuf.setLen(oldLen + data.len)
  for i, b in data:
    s.inBuf[oldLen + i] = b

proc takeOutput*(s: WolfTlsSession): seq[byte] =
  result = s.outBuf
  s.outBuf = @[]

proc version*(s: WolfTlsSession): string =
  if s.isNil or s.ssl.isNil:
    return ""
  $wolfSSL_get_version(s.ssl)

proc errorCode*(s: WolfTlsSession, ret: cint): cint =
  wolfSSL_get_error(s.ssl, ret)

proc wantsIo(s: WolfTlsSession, ret: cint): bool =
  let err = s.errorCode(ret)
  err == WolfSslErrorWantRead or err == WolfSslErrorWantWrite

proc acceptStep*(s: WolfTlsSession): int =
  let ret = wolfSSL_accept(s.ssl)
  if ret == 1: return 1
  if s.wantsIo(ret): return 0
  -s.errorCode(ret)

proc readPlainStep*(s: WolfTlsSession, dst: var openArray[byte]): int =
  let ret = wolfSSL_read(s.ssl, addr dst[0], cint(dst.len))
  if ret > 0: return int(ret)
  if s.wantsIo(ret): return 0
  -s.errorCode(ret)

proc writePlainStep*(s: WolfTlsSession, data: openArray[byte]): int =
  if data.len == 0: return 0
  let ret = wolfSSL_write(s.ssl, unsafeAddr data[0], cint(data.len))
  if ret > 0: return int(ret)
  if s.wantsIo(ret): return 0
  -s.errorCode(ret)

proc flushOutput*(c: WolfTlsConnection): Future[void] {.async: (raises: [TransportError, CancelledError]).} =
  let outData = c.session.takeOutput()
  if outData.len > 0:
    discard await c.raw.write(outData)

proc feedEncrypted*(c: WolfTlsConnection): Future[void] {.async: (raises: [TransportError, CancelledError, WolfTlsClosedError]).} =
  var buf = newSeq[byte](WolfEncryptedReadChunk)
  let n = await c.raw.readOnce(addr buf[0], buf.len)
  if n <= 0:
    raise newException(WolfTlsClosedError, "TLS peer closed transport")
  buf.setLen(n)
  c.session.feed(buf)

proc ensureHandshake*(c: WolfTlsConnection): Future[void] {.async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  if c.handshakeDone:
    return
  while true:
    let rc = c.session.acceptStep()
    await c.flushOutput()
    if rc == 1:
      c.handshakeDone = true
      return
    if rc < 0:
      if -rc == WolfSslErrorZeroReturn:
        raise newException(WolfTlsClosedError, "TLS peer closed during handshake")
      raise newException(WolfTlsError, "wolfSSL_accept failed: " & $(-rc))
    await c.feedEncrypted()

proc readPlainSome*(c: WolfTlsConnection, maxBytes: int): Future[seq[byte]] {.async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  await c.ensureHandshake()
  while true:
    result = newSeq[byte](maxBytes)
    let rc = c.session.readPlainStep(result)
    await c.flushOutput()
    if rc > 0:
      result.setLen(rc)
      return
    if rc < 0:
      if -rc == WolfSslErrorZeroReturn:
        raise newException(WolfTlsClosedError, "TLS peer closed connection")
      raise newException(WolfTlsError, "wolfSSL_read failed: " & $(-rc))
    await c.feedEncrypted()

proc writePlain*(c: WolfTlsConnection, data: seq[byte]): Future[void] {.async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  await c.ensureHandshake()
  var offset = 0
  while offset < data.len:
    let rc = c.session.writePlainStep(data.toOpenArray(offset, data.len - 1))
    await c.flushOutput()
    if rc > 0:
      offset += rc
    elif rc < 0:
      if -rc == WolfSslErrorZeroReturn:
        raise newException(WolfTlsClosedError, "TLS peer closed connection")
      raise newException(WolfTlsError, "wolfSSL_write failed: " & $(-rc))
    else:
      await c.feedEncrypted()
