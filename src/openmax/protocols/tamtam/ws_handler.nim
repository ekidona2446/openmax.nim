import std/[json, strutils, strformat, logging, tables]
import chronos
import websock/websock
import ../../core/app_context
import ../../core/calls_state
import ../../core/opcodes
import ../../proto/mobile_rpc
import ../../crypto/sha256
import ../../db/store
import ../../db/sqlite_abi
import ../auth_utils
import ../errors

## Minimal TamTam JSON/WebSocket RPC handler.
##
## It mirrors the already implemented TamTam TCP auth subset, but speaks the
## WebProto JSON envelope used by the Python OpenMAX websocket transport:
##   {"ver": 10/11, "cmd": ..., "seq": ..., "opcode": ..., "payload": ...}
##
## Implemented opcodes: session init, ping, log, auth request, auth/code check,
## auth confirm, login and calls/OK token. Everything else returns NOT_IMPLEMENTED.

type
  WsConnectionState = ref object
    currentUserId: int64
    currentSessionToken: string
    deviceType: string
    deviceName: string
    appVersion: string

proc safeInfo(message: string) =
  try:
    info message
  except Exception:
    discard

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(data[i])

proc reqInt(frame: JsonNode, key: string, defaultValue = 0): int =
  if frame.kind == JObject and frame.hasKey(key):
    try: return frame[key].getInt()
    except CatchableError: discard
  defaultValue

proc reqPayload(frame: JsonNode): JsonNode =
  if frame.kind == JObject and frame.hasKey("payload"):
    frame["payload"]
  else:
    newJObject()

proc sendFrame(ws: WSSession, req: JsonNode, cmd: int, opcode: int, payload: JsonNode): Future[void] {.async.} =
  let response = %*{
    "ver": reqInt(req, "ver", 11),
    "cmd": cmd,
    "seq": reqInt(req, "seq", 0),
    "opcode": opcode,
    "payload": payload
  }
  await ws.send($response)

proc sendOk(ws: WSSession, req: JsonNode, opcode: int, payload: JsonNode): Future[void] {.async.} =
  await sendFrame(ws, req, int(CmdOk), opcode, payload)

proc errorToJson(payload: ErrorPayload): JsonNode =
  %*{
    "localizedMessage": payload.localizedMessage,
    "error": payload.error,
    "message": payload.message,
    "title": payload.title
  }

proc sendErr(ws: WSSession, req: JsonNode, opcode: int, payload: ErrorPayload): Future[void] {.async.} =
  await sendFrame(ws, req, int(CmdErr), opcode, errorToJson(payload))

proc ttProfileJson(user: DbRow): JsonNode =
  let firstName = rowString(user, "firstname")
  let lastName = rowString(user, "lastname")
  let displayName = if lastName.len > 0: firstName & " " & lastName else: firstName
  %*{
    "id": rowInt64(user, "id"),
    "updateTime": rowInt64(user, "updatetime"),
    "phone": rowInt64(user, "phone"),
    "names": [{
      "name": displayName,
      "type": "TT"
    }],
    "options": rowStringSeq(user, "options"),
    "description": rowString(user, "description"),
    "link": ""
  }

proc deviceTypeOrDefault(state: WsConnectionState, payload: JsonNode): string =
  let payloadValue = payload{"deviceType"}.getStr("")
  if payloadValue.len > 0:
    payloadValue
  elif state.deviceType.len > 0:
    state.deviceType
  else:
    "WEB"

proc deviceNameOrDefault(state: WsConnectionState): string =
  if state.deviceName.len > 0: state.deviceName else: "WebSocket"

proc handleSessionInit(ws: WSSession, req: JsonNode, state: WsConnectionState): Future[void] {.async.} =
  let payload = reqPayload(req)
  let ua = payload{"userAgent"}
  if ua.kind == JObject:
    state.deviceType = ua{"deviceType"}.getStr("")
    state.deviceName = ua{"deviceName"}.getStr("")
    state.appVersion = ua{"appVersion"}.getStr("")

  let country =
    if ua.kind == JObject:
      countryFromUserAgent(ua{"locale"}.getStr(""), ua{"deviceLocale"}.getStr(""), "RU")
    else:
      "RU"
  await ws.sendOk(req, SessionInitOpcode.int, %*{
    "proxy": "",
    "logs-enabled": false,
    "proxy-domains": [],
    "location": country,
    "libh-enabled": false,
    "phone-auto-complete-enabled": false
  })

proc handleAuthRequest(app: AppContext, ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  let phone = normalizePhoneNumber(payload{"phone"}.getStr(""))
  if phone.len == 0:
    await ws.sendErr(req, AuthRequestOpcode.int, invalidPayloadError())
    return

  let existingUser = app.db.findUserByPhone(phone)
  let state = if existingUser.len == 0: "register" else: "started"
  let authToken = generateRandomString(128)
  let verifyCode = generateCode()
  app.db.insertAuthToken(phone, authToken, verifyCode, nowUnix() + 300, state)

  await ws.sendOk(req, AuthRequestOpcode.int, %*{
    "verifyToken": authToken,
    "retries": 5,
    "codeDelay": 60,
    "codeLength": 6,
    "callDelay": 0,
    "requestType": "SMS"
  })
  safeInfo(&"[tamtam/ws] auth_request phone={phone} code={verifyCode} existing={existingUser.len != 0}")

proc handleAuth(app: AppContext, ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  # Some clients use `token`, others mirror the response field name.
  let token = block:
    let v = payload{"token"}.getStr("")
    if v.len > 0: v else: payload{"verifyToken"}.getStr("")
  let code = payload{"verifyCode"}.getStr("")
  if token.len == 0 or code.len == 0:
    await ws.sendErr(req, AuthOpcode.int, invalidPayloadError())
    return

  let stored = app.db.findAuthToken(token)
  if stored.len == 0:
    await ws.sendErr(req, AuthOpcode.int, codeExpiredError())
    return

  if rowString(stored, "code_hash") != sha256Hex(code):
    await ws.sendErr(req, AuthOpcode.int, invalidCodeError())
    return

  let phone = rowString(stored, "phone")
  if rowString(stored, "state") == "register":
    app.db.updateAuthTokenState(token, "verified")
    await ws.sendOk(req, AuthOpcode.int, %*{
      "tokenAttrs": {"NEW": {"token": token}},
      "tokenTypes": {"NEW": token}
    })
    return

  let user = app.db.findUserByPhone(phone)
  if user.len == 0:
    await ws.sendErr(req, AuthOpcode.int, userNotFoundError())
    return

  app.db.updateAuthTokenState(token, "verified")
  await ws.sendOk(req, AuthOpcode.int, %*{
    "profile": ttProfileJson(user),
    "tokenAttrs": {"AUTH": {"token": token}},
    "tokenTypes": {"AUTH": token}
  })

proc handleAuthConfirm(app: AppContext,
                       ws: WSSession,
                       req: JsonNode,
                       state: WsConnectionState,
                       peer: string): Future[void] {.async.} =
  let payload = reqPayload(req)
  let token = payload{"token"}.getStr("")
  if token.len == 0:
    await ws.sendErr(req, AuthConfirmOpcode.int, invalidPayloadError())
    return

  let stored = app.db.findAuthToken(token)
  if stored.len == 0:
    await ws.sendErr(req, AuthConfirmOpcode.int, invalidTokenError())
    return

  let storedState = rowString(stored, "state")
  if storedState == "started" or storedState == "register":
    await ws.sendErr(req, AuthConfirmOpcode.int, invalidTokenError())
    return

  let phone = rowString(stored, "phone")
  var user = app.db.findUserByPhone(phone)
  if user.len == 0:
    let name = block:
      let explicit = payload{"name"}.getStr("").strip()
      if explicit.len > 0: explicit else: payload{"firstName"}.getStr("").strip()
    if name.len == 0 or name.len > 59:
      await ws.sendErr(req, AuthConfirmOpcode.int, invalidPayloadError())
      return
    user = app.db.createTamtamUser(phone, name)

  app.db.deleteAuthToken(token)
  let loginToken = generateRandomString(128)
  app.db.insertSessionToken(
    phone,
    loginToken,
    deviceTypeOrDefault(state, payload),
    deviceNameOrDefault(state),
    peer,
    nowUnixMs()
  )

  let userId = rowInt64(user, "id")
  await ws.sendOk(req, AuthConfirmOpcode.int, %*{
    "userToken": userId,
    "profile": ttProfileJson(user),
    "tokenType": "LOGIN",
    "token": loginToken
  })
  safeInfo(&"[tamtam/ws] auth_confirm finished phone={phone} userId={userId}")

proc handleLogin(app: AppContext, ws: WSSession, req: JsonNode, state: WsConnectionState): Future[void] {.async.} =
  let payload = reqPayload(req)
  let token = payload{"token"}.getStr("")
  let session = app.db.findSessionToken(token)
  if session.len == 0:
    await ws.sendErr(req, LoginOpcode.int, invalidTokenError())
    return

  let user = app.db.findUserByPhone(rowString(session, "phone"))
  if user.len == 0:
    await ws.sendErr(req, LoginOpcode.int, userNotFoundError())
    return

  state.currentUserId = rowInt64(user, "id")
  state.currentSessionToken = token
  await ws.sendOk(req, LoginOpcode.int, %*{
    "profile": ttProfileJson(user),
    "token": token,
    "time": nowUnixMs(),
    "config": {"hash": "0"}
  })


proc handleLogout(app: AppContext, ws: WSSession, req: JsonNode, state: WsConnectionState): Future[void] {.async.} =
  if state.currentSessionToken.len > 0:
    app.db.deleteSessionToken(state.currentSessionToken)
  state.currentUserId = 0
  state.currentSessionToken = ""
  await ws.sendOk(req, LogoutOpcode.int, newJNull())

proc handleCallsToken(app: AppContext, ws: WSSession, req: JsonNode, currentUserId: int64): Future[void] {.async.} =
  if currentUserId == 0:
    await ws.sendErr(req, OkTokenOpcode.int, invalidTokenError())
    return
  let token = "openmax-call:" & $currentUserId & ":" & generateRandomString(64)
  app.calls.registerCallToken(token, currentUserId)
  await ws.sendOk(req, OkTokenOpcode.int, %*{
    "token": token
  })

proc handleWsFrame(app: AppContext, ws: WSSession, req: JsonNode, state: WsConnectionState, peer: string): Future[void] {.async.} =
  let opcode = reqInt(req, "opcode", 0)
  case uint16(opcode)
  of SessionInitOpcode:
    await handleSessionInit(ws, req, state)
  of PingOpcode:
    await ws.sendOk(req, PingOpcode.int, newJNull())
  of LogOpcode:
    await ws.sendOk(req, LogOpcode.int, newJNull())
  of AuthRequestOpcode:
    await handleAuthRequest(app, ws, req)
  of AuthOpcode:
    await handleAuth(app, ws, req)
  of AuthConfirmOpcode:
    await handleAuthConfirm(app, ws, req, state, peer)
  of LoginOpcode:
    await handleLogin(app, ws, req, state)
  of LogoutOpcode:
    await handleLogout(app, ws, req, state)
  of OkTokenOpcode:
    await handleCallsToken(app, ws, req, state.currentUserId)
  else:
    await ws.sendErr(req, opcode, notImplementedError())

proc handleTamtamWebSocket*(app: AppContext, ws: WSSession, peer: string): Future[void] {.async.} =
  let state = WsConnectionState(currentUserId: 0, currentSessionToken: "", deviceType: "", deviceName: "", appVersion: "")
  safeInfo(&"[tamtam/ws] connected peer={peer}")
  try:
    while ws.readyState != ReadyState.Closed:
      let msg = await ws.recvMsg()
      if ws.readyState == ReadyState.Closed:
        break
      let raw = bytesToString(msg)
      let req =
        try:
          parseJson(raw)
        except JsonParsingError:
          await ws.send($(%*{"ver": 11, "cmd": int(CmdErr), "seq": 0, "opcode": 0, "payload": errorToJson(invalidPayloadError())}))
          continue
      await handleWsFrame(app, ws, req, state, peer)
  except WebSocketError as exc:
    if exc.msg.contains("Invalid UTF8 sequence detected in close reason"):
      safeInfo(&"[tamtam/ws] websocket close peer={peer}: invalid/empty close reason")
    else:
      safeInfo(&"[tamtam/ws] websocket error peer={peer}: {exc.msg}")
  except CatchableError as exc:
    safeInfo(&"[tamtam/ws] handler error peer={peer}: {exc.msg}")
  finally:
    safeInfo(&"[tamtam/ws] disconnected peer={peer} user={state.currentUserId}")
