import std/[logging, strformat, strutils, os]
import chronos
import chronicles
import websock/websock
import ../core/protocols
import ../core/app_context
import ../core/connection_context
import ../proto/mobile_frame
import ../tls/wolf_tls
import ../protocols/router
import ../protocols/oneme/ws_handler

type
  ListenerRuntime* = ref object
    app*: AppContext
    spec*: ListenerSpec
    server*: StreamServer

proc safeInfo(message: string) =
  try:
    info message
  except Exception:
    discard

proc safeWarn(message: string) =
  try:
    warn message
  except Exception:
    discard

proc peerLabel(transp: StreamTransport): string =
  try:
    $transp.remoteAddress()
  except TransportOsError:
    "unknown-peer"

proc parseDualStackMode(value: string): DualStackType =
  case value.toLowerAscii()
  of "disabled", "off", "false", "0":
    DualStackType.Disabled
  of "enabled", "on", "true", "1":
    DualStackType.Enabled
  else:
    DualStackType.Auto

proc resolveTlsPath(path: string): string =
  if path.isAbsolute(): path else: getCurrentDir() / path

proc handleTcpClient(runtime: ListenerRuntime,
                     rawTransp: StreamTransport): Future[void] {.async: (raises: []).} =
  let peer = peerLabel(rawTransp)
  let ctx = newConnectionContext(runtime.app, runtime.spec.protocol, peer)
  safeInfo(&"[transport] tcp client connected: {runtime.spec.protocol} {peer} tls={runtime.spec.tls_enabled}")

  let transp =
    try:
      if runtime.spec.tls_enabled:
        let keyPath = resolveTlsPath(runtime.app.config.tls.key_file)
        let certPath = resolveTlsPath(runtime.app.config.tls.cert_file)
        if not fileExists(keyPath) or not fileExists(certPath):
          safeWarn(&"[transport] tcp TLS requested but cert/key not found: cert={certPath} key={keyPath}")
          await rawTransp.closeWait()
          return
        newTlsMobileTransport(rawTransp, newWolfTlsContext(certPath, keyPath))
      else:
        newPlainMobileTransport(rawTransp)
    except CatchableError as exc:
      safeWarn(&"[transport] failed to initialize tcp transport for {peer}: {exc.msg}")
      await rawTransp.closeWait()
      return

  try:
    while true:
      let frame = await transp.readFrame()
      await dispatchTcpFrame(ctx, transp, frame)
  except MobileFrameError as exc:
    safeWarn(&"[transport] invalid mobile frame from {peer}: {exc.msg}")
  except TransportIncompleteError:
    safeInfo(&"[transport] tcp client disconnected: {runtime.spec.protocol} {peer}")
  except TransportError as exc:
    safeWarn(&"[transport] tcp client transport error from {peer}: {exc.msg}")
  except AsyncStreamError as exc:
    safeWarn(&"[transport] tcp client stream error from {peer}: {exc.msg}")
  except CancelledError:
    safeInfo(&"[transport] tcp client cancelled: {runtime.spec.protocol} {peer}")
  except CatchableError as exc:
    safeWarn(&"[transport] tcp client handler error from {peer}: {exc.msg}")
  finally:
    try:
      runtime.app.detachClient(ctx.currentUserId, transp)
    except CatchableError:
      discard
    await transp.closeWait()

proc serveTcp(runtime: ListenerRuntime): Future[void] {.async: (raises: []).} =
  let bindAddress =
    try:
      initTAddress(runtime.spec.host, Port(runtime.spec.port))
    except TransportAddressError as exc:
      safeWarn(&"[transport] invalid bind address for {runtime.spec.describe()}: {exc.msg}")
      return

  let dualstackValue =
    if runtime.spec.dualstack_mode.len > 0:
      runtime.spec.dualstack_mode
    else:
      runtime.app.config.server.dualstack_mode
  let dualstackMode = parseDualStackMode(dualstackValue)

  try:
    runtime.server = createStreamServer(
      bindAddress,
      flags = {ReuseAddr},
      bufferSize = DefaultMaxPayloadSize,
      dualstack = dualstackMode
    )
  except TransportOsError as exc:
    safeWarn(&"[transport] failed to bind {runtime.spec.describe()}: {exc.msg}")
    return

  safeInfo(&"[transport] tcp listener started: {runtime.spec.describe()} dualstack={dualstackValue}")

  block acceptLoop:
    while true:
      let transp =
        try:
          await runtime.server.accept()
        except TransportTooManyError:
          safeWarn(&"[transport] too many open transports on {runtime.spec.describe()}")
          continue
        except TransportAbortedError:
          continue
        except TransportUseClosedError:
          break acceptLoop
        except TransportOsError as exc:
          safeWarn(&"[transport] accept failed on {runtime.spec.describe()}: {exc.msg}")
          break acceptLoop
        except CancelledError:
          break acceptLoop

      if not isNil(transp):
        asyncSpawn handleTcpClient(runtime, transp)

  if not isNil(runtime.server):
    runtime.server.close()
    await noCancel(runtime.server.join())

proc serveWebSocket(runtime: ListenerRuntime): Future[void] {.async: (raises: [CancelledError]).} =
  let bindAddress =
    try:
      initTAddress(runtime.spec.host, Port(runtime.spec.port))
    except TransportAddressError as exc:
      safeWarn(&"[transport] invalid websocket bind address for {runtime.spec.describe()}: {exc.msg}")
      return

  proc handleRequest(request: HttpRequest) {.async.} =
    let peer = "ws-peer"

    try:
      let server = WSServer.new()
      let ws = await server.handleRequest(request)
      if ws.readyState != ReadyState.Open:
        safeWarn(&"[transport] websocket upgrade failed: {runtime.spec.describe()} peer={peer}")
        return

      case runtime.spec.protocol
      of pkOneme:
        await runtime.app.handleOnemeWebSocket(ws, peer)
      of pkTamtam:
        safeWarn(&"[transport] tamtam websocket handler is not implemented yet: peer={peer}")
        await ws.close()
    except WebSocketError as exc:
      safeWarn(&"[transport] websocket error on {runtime.spec.describe()} peer={peer}: {exc.msg}")
    except CatchableError as exc:
      safeWarn(&"[transport] websocket request error on {runtime.spec.describe()} peer={peer}: {exc.msg}")

  let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
  let server =
    try:
      if runtime.spec.tls_enabled:
        let keyPath = resolveTlsPath(runtime.app.config.tls.key_file)
        let certPath = resolveTlsPath(runtime.app.config.tls.cert_file)
        if not fileExists(keyPath) or not fileExists(certPath):
          safeWarn(&"[transport] websocket TLS requested but cert/key not found: cert={certPath} key={keyPath}")
          return
        HttpServer.create(
          bindAddress,
          tlsPrivateKey = TLSPrivateKey.init(readFile(keyPath)),
          tlsCertificate = TLSCertificate.init(readFile(certPath)),
          handler = handleRequest,
          flags = socketFlags
        )
      else:
        HttpServer.create(bindAddress, handleRequest, flags = socketFlags)
    except CatchableError as exc:
      safeWarn(&"[transport] failed to bind websocket {runtime.spec.describe()}: {exc.msg}")
      return

  safeInfo(&"[transport] websocket listener started: {runtime.spec.describe()} tls={runtime.spec.tls_enabled}")
  try:
    server.start()
  except TransportOsError as exc:
    safeWarn(&"[transport] failed to start websocket {runtime.spec.describe()}: {exc.msg}")
    return
  await server.join()

proc newListenerRuntime*(app: AppContext, spec: ListenerSpec): ListenerRuntime =
  ListenerRuntime(app: app, spec: spec)

proc start*(runtime: ListenerRuntime): Future[void] {.async: (raises: [CancelledError]).} =
  case runtime.spec.transport
  of tkTcp:
    await runtime.serveTcp()
  of tkWebSocket:
    await runtime.serveWebSocket()
