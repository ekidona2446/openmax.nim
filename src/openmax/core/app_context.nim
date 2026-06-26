import std/[tables, sequtils, strutils]
import ../config/types
import ../db/store
import ../proto/mobile_frame
import ./calls_state

type
  AppContext* = ref object
    config*: AppConfig
    db*: AppDatabase
    clientsByUser*: Table[int64, seq[MobileTransport]]
    calls*: CallsState

proc newAppContext*(config: AppConfig, db: AppDatabase): AppContext =
  AppContext(
    config: config,
    db: db,
    clientsByUser: initTable[int64, seq[MobileTransport]](),
    calls: newCallsState()
  )

# ---------------------------------------------------------------------------
# Resolved Calls configuration helpers (apply sane defaults to the raw config).
# ---------------------------------------------------------------------------

proc callsEnabled*(app: AppContext): bool =
  app.config.calls.enabled

proc callsApplicationKey*(app: AppContext): string =
  if app.config.calls.application_key.len > 0:
    app.config.calls.application_key
  else:
    "CNHIJPLGDIHBABABA"          ## same key the reference MAX client uses

proc callsSignalingPath*(app: AppContext): string =
  let p = app.config.calls.signaling_path.strip()
  if p.len == 0: "/websocket"
  elif p.startsWith("/"): p
  else: "/" & p

proc callsSessionTtl*(app: AppContext): int =
  if app.config.calls.session_ttl_seconds > 0: app.config.calls.session_ttl_seconds
  else: 3600

proc callsTokenTtl*(app: AppContext): int =
  if app.config.calls.token_ttl_seconds > 0: app.config.calls.token_ttl_seconds
  else: 300

proc callsSignalingHost*(app: AppContext): string =
  if app.config.calls.signaling_host.len > 0:
    app.config.calls.signaling_host
  else:
    app.config.server.host.strip(chars = {'[', ']'})

proc callsSignalingPort*(app: AppContext): int =
  if app.config.calls.signaling_port > 0:
    app.config.calls.signaling_port
  else:
    app.config.protocols.oneme_ws_port

proc callsSignalingEndpoint*(app: AppContext, query: string): string =
  ## Build the wss:// (or ws://) endpoint advertised to clients.
  let host = app.callsSignalingHost()
  let displayHost = if host.contains(":"): "[" & host & "]" else: host
  let scheme = if app.config.tls.enabled: "wss" else: "ws"
  let path = app.callsSignalingPath()
  let port = app.callsSignalingPort()
  let q = if query.len > 0: "?" & query else: ""
  scheme & "://" & displayHost & ":" & $port & path & q

proc attachClient*(app: AppContext, userId: int64, transp: MobileTransport) =
  if userId == 0 or transp.isNil:
    return
  var clients = app.clientsByUser.getOrDefault(userId, @[])
  if clients.allIt(it != transp):
    clients.add transp
  app.clientsByUser[userId] = clients

proc detachClient*(app: AppContext, userId: int64, transp: MobileTransport) =
  if userId == 0 or transp.isNil or not app.clientsByUser.hasKey(userId):
    return
  let clients = app.clientsByUser[userId].filterIt(it != transp)
  if clients.len == 0:
    app.clientsByUser.del(userId)
  else:
    app.clientsByUser[userId] = clients

proc transportsForUser*(app: AppContext, userId: int64): seq[MobileTransport] =
  app.clientsByUser.getOrDefault(userId, @[])
