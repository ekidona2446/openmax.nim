import std/[logging, strformat, strutils]
import chronos
import ../core/protocols
import ../core/app_context
import ../core/connection_context
import ../proto/mobile_frame
import ../protocols/router

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

proc handleTcpClient(runtime: ListenerRuntime,
                     transp: StreamTransport): Future[void] {.async: (raises: []).} =
  let peer = peerLabel(transp)
  let ctx = newConnectionContext(runtime.app, runtime.spec.protocol, peer)
  safeInfo(&"[transport] tcp client connected: {runtime.spec.protocol} {peer}")

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

proc newListenerRuntime*(app: AppContext, spec: ListenerSpec): ListenerRuntime =
  ListenerRuntime(app: app, spec: spec)

proc start*(runtime: ListenerRuntime): Future[void] {.async: (raises: [CancelledError]).} =
  case runtime.spec.transport
  of tkTcp:
    await runtime.serveTcp()
  of tkWebSocket:
    safeInfo(&"[transport] websocket listener placeholder: {runtime.spec.describe()}")
    while true:
      await sleepAsync(1.hours)
