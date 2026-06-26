## Calls API — HTTP endpoint served at POST /fb.do.
##
## Implements the two methods documented by the maxcalls reference
## (icyfalc0n/maxcalls @ master, docs/api/calls.md):
##
##   * auth.anonymLogin       -> exchange a OneMe call-token for a Calls session
##   * vchat.startConversation -> create a conversation and hand back the
##                                signaling endpoint + TURN/STUN configuration
##
## Media relay itself is delegated to an external coturn (advertised verbatim
## from [calls] in the config); this server only signals.

import std/[json, strutils, uri, tables]
import chronos, httputils, websock/http/common
import ../core/app_context
import ../core/calls_state
import ../core/opcodes
import ../proto/mobile_frame
import ../proto/mobile_rpc
import ../proto/msgpack_codec
import ./auth_utils

const MaxFormBodyBytes = 64 * 1024

# ---------------------------------------------------------------------------
# application/x-www-form-urlencoded parsing
# ---------------------------------------------------------------------------

proc parseFormUrlEncoded(body: string): Table[string, string] =
  result = initTable[string, string]()
  for pair in body.split('&'):
    if pair.len == 0:
      continue
    let eq = pair.find('=')
    if eq < 0:
      result[decodeUrl(pair)] = ""
    else:
      let key = decodeUrl(pair[0 ..< eq])
      let value = decodeUrl(pair[eq + 1 .. ^1])
      result[key] = value

proc readBody(request: HttpRequest): Future[string] {.async.} =
  ## Read up to MaxFormBodyBytes of the request body.
  var collected = ""
  var buf = newSeq[byte](16 * 1024)
  while collected.len < MaxFormBodyBytes:
    let n = await request.stream.reader.readOnce(addr buf[0], buf.len)
    if n <= 0:
      break
    var chunk = newString(n)
    for i in 0 ..< n:
      chunk[i] = char(buf[i])
    collected.add chunk
    if n < buf.len:
      break
  collected

# ---------------------------------------------------------------------------
# JSON error helpers (shape mirrors the reference Calls API error responses)
# ---------------------------------------------------------------------------

proc callsError(code, message: string): string =
  $(%*{"error": {"code": code, "message": message}})

proc sendJson(request: HttpRequest, status: HttpCode, content: string): Future[void] {.async.} =
  await request.sendResponse(status, content = content)

# ---------------------------------------------------------------------------
# IncomingCall fan-out (mobile protocol opcode 137)
# ---------------------------------------------------------------------------

proc notifyFrame(opcode: uint16): MobileFrame =
  MobileFrame(
    header: MobileHeader(
      ver: ProtoVer, cmd: 0'u8, seq: 0'u16,
      opcode: opcode, compressionFlag: 0'u8, payloadLength: 0
    ),
    payload: @[]
  )

proc notifyIncomingCall(app: AppContext, calleeUserId: int64, payload: JsonNode) {.async: (raises: []).} =
  ## Best-effort push of an IncomingCall to every live transport of the callee.
  if calleeUserId == 0:
    return
  let bytes =
    try:
      packJsonPayload(payload)
    except MsgPackCodecError:
      return
  let frame = notifyFrame(NotifVideoChatStartOpcode)
  for client in app.transportsForUser(calleeUserId):
    try:
      await client.sendResponseBytes(frame, 0'u8, NotifVideoChatStartOpcode, bytes)
    except CatchableError:
      discard

# ---------------------------------------------------------------------------
# auth.anonymLogin
# ---------------------------------------------------------------------------

proc handleAnonymLogin(app: AppContext, request: HttpRequest,
                       form: Table[string, string]): Future[void] {.async.} =
  let sessionDataRaw = form.getOrDefault("session_data", "")
  if sessionDataRaw.len == 0:
    await request.sendJson(Http400, callsError("session_data.missing", "session_data is required"))
    return

  let sessionData =
    try:
      parseJson(sessionDataRaw)
    except CatchableError:
      await request.sendJson(Http400, callsError("session_data.invalid", "session_data is not valid JSON"))
      return

  let authToken = sessionData{"auth_token"}.getStr("")
  if authToken.len == 0:
    await request.sendJson(Http400, callsError("auth_token.missing", "auth_token is required"))
    return

  let userId = app.calls.resolveCallToken(authToken, app.callsTokenTtl())
  if userId == 0:
    await request.sendJson(Http401, callsError("auth.token.invalid", "Call token is invalid or expired"))
    return

  let externalUserId = app.calls.externalIdFor(userId)
  let sessionKey = "sk_" & generateRandomString(40)
  let sessionSecret = "ss_" & generateRandomString(48)
  discard app.calls.createSession(userId, sessionKey, sessionSecret, externalUserId)

  let resp = %* {
    "uid": $userId,
    "session_key": sessionKey,
    "session_secret_key": sessionSecret,
    "api_server": (if app.config.tls.enabled: "https://" else: "http://") &
                  app.callsSignalingHost(),
    "external_user_id": externalUserId
  }
  await request.sendJson(Http200, $resp)

# ---------------------------------------------------------------------------
# vchat.startConversation
# ---------------------------------------------------------------------------

proc handleStartConversation(app: AppContext, request: HttpRequest,
                             form: Table[string, string]): Future[void] {.async.} =
  let sessionKey = form.getOrDefault("session_key", "")
  let (ok, session) = app.calls.resolveSession(sessionKey, app.callsSessionTtl())
  if not ok:
    await request.sendJson(Http401, callsError("session.invalid", "session_key is invalid or expired"))
    return

  let conversationId = form.getOrDefault("conversationId", "")
  if conversationId.len == 0:
    await request.sendJson(Http400, callsError("conversationId.missing", "conversationId is required"))
    return

  let calleeExternal = form.getOrDefault("externalIds", "").split(',')[0].strip()
  if calleeExternal.len == 0:
    await request.sendJson(Http400, callsError("externalIds.missing", "externalIds is required"))
    return

  let isVideo = form.getOrDefault("isVideo", "false").toLowerAscii() == "true"
  let calleeUserId = app.calls.userIdForExternal(calleeExternal)

  discard app.calls.createConversation(
    conversationId = conversationId,
    callerUserId = session.userId,
    calleeUserId = calleeUserId,
    callerExternal = session.externalUserId,
    calleeExternal = calleeExternal,
    isVideo = isVideo
  )

  # One-time signaling token granting the caller access to this conversation WS.
  let signalingToken = generateRandomString(48)
  app.calls.addSignalingToken(conversationId, signalingToken, session.userId)

  let query = encodeQuery({
    "userId": $session.userId,
    "entityType": "USER",
    "conversationId": conversationId,
    "token": signalingToken
  })
  let endpoint = app.callsSignalingEndpoint(query)

  # If the callee is a known local user, mint their signaling token and push an
  # IncomingCall so their client can authenticate and join the same conversation.
  if calleeUserId != 0:
    let calleeToken = generateRandomString(48)
    app.calls.addSignalingToken(conversationId, calleeToken, calleeUserId)
    let calleeQuery = encodeQuery({
      "userId": $calleeUserId,
      "entityType": "USER",
      "conversationId": conversationId,
      "token": calleeToken
    })
    let incoming = %* {
      "conversationId": conversationId,
      "callerId": session.userId,
      "callerExternalId": session.externalUserId,
      "isVideo": isVideo,
      # vcp mirrors the reference IncomingCall: signaling endpoint + token,
      # so the callee can connect without calling vchat.startConversation.
      "vcp": {
        "wse": app.callsSignalingEndpoint(""),
        "tkn": calleeToken,
        "endpoint": app.callsSignalingEndpoint(calleeQuery)
      }
    }
    asyncSpawn notifyIncomingCall(app, calleeUserId, incoming)

  var stunUrls = newJArray()
  for u in app.config.calls.stun_urls:
    stunUrls.add %u
  var turnUrls = newJArray()
  for u in app.config.calls.turn_urls:
    turnUrls.add %u

  let resp = %* {
    "turn_server": {
      "urls": turnUrls,
      "username": app.config.calls.turn_username,
      "credential": app.config.calls.turn_credential
    },
    "stun_server": {
      "urls": stunUrls
    },
    "endpoint": endpoint
  }
  await request.sendJson(Http200, $resp)

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

proc handleCallsHttp*(app: AppContext, request: HttpRequest): Future[void] {.async.} =
  try:
    if not app.callsEnabled():
      await request.sendJson(Http404, callsError("calls.disabled", "Calls API is disabled"))
      return
    if request.meth != HttpMethod.MethodPost:
      await request.sendJson(Http405, "Method Not Allowed")
      return

    let body = await readBody(request)
    let form = parseFormUrlEncoded(body)

    # format is documented as always "JSON"; we only ever emit JSON anyway.
    if form.getOrDefault("application_key", "") != app.callsApplicationKey():
      await request.sendJson(Http403, callsError("application_key.invalid", "Invalid application_key"))
      return

    case form.getOrDefault("method", "")
    of "auth.anonymLogin":
      await handleAnonymLogin(app, request, form)
    of "vchat.startConversation":
      await handleStartConversation(app, request, form)
    else:
      await request.sendJson(Http400, callsError("method.unknown", "Unknown or missing method"))
  except CatchableError as exc:
    await request.sendJson(Http500, callsError("internal", exc.msg))
