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

type
  WsConnectionState = ref object
    currentUserId: int64
    currentSessionToken: string

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

proc profileJson(user: DbRow): JsonNode =
  let firstName = rowString(user, "firstname")
  let lastName = rowString(user, "lastname")
  let displayName = if lastName.len > 0: firstName & " " & lastName else: firstName
  %*{
    "contact": {
      "id": rowInt64(user, "id"),
      "updateTime": rowInt64(user, "updatetime"),
      "phone": rowInt64(user, "phone"),
      "names": [{
        "name": displayName,
        "firstName": firstName,
        "lastName": lastName,
        "type": "ONEME"
      }],
      "options": rowStringSeq(user, "options"),
      "accountStatus": rowInt64(user, "accountstatus").int,
      "location": countryForUserRow(user),
      "registrationTime": nowUnixMs(),
      "description": rowString(user, "description"),
      "link": ""
    },
    "profileOptions": []
  }

proc handleSessionInit(ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  let ua = payload{"userAgent"}
  let country =
    if ua.kind == JObject:
      countryFromUserAgent(ua{"locale"}.getStr(""), ua{"deviceLocale"}.getStr(""), "RU")
    else:
      "RU"
  await ws.sendOk(req, SessionInitOpcode.int, %*{
    "callsSeed": nowUnixMs(),
    "location": country,
    "app-update-type": 0,
    "reg-country-code": [country],
    "phone-auto-complete-enabled": false,
    "qr-auth-enabled": false,
    "lang": true
  })

proc handleAuthRequest(app: AppContext, ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  let phone = normalizePhoneNumber(payload{"phone"}.getStr(""))
  if phone.len == 0:
    await ws.sendErr(req, AuthRequestOpcode.int, invalidPayloadError())
    return

  let existingUser = app.db.findUserByPhone(phone)
  let state = if existingUser.len == 0: "register" else: ""
  let authToken = generateRandomString(96)
  let verifyCode = generateCode()
  app.db.insertAuthToken(phone, authToken, verifyCode, nowUnix() + 300, state)

  await ws.sendOk(req, AuthRequestOpcode.int, %*{
    "token": authToken,
    "codeLength": 6,
    "requestMaxDuration": 60000,
    "requestCountLeft": 10,
    "altActionDuration": 60000
  })
  safeInfo(&"[oneme/ws] auth_request phone={phone} code={verifyCode} existing={existingUser.len != 0}")

proc handleAuth(app: AppContext, ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  let token = payload{"token"}.getStr("")
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
      "tokenAttrs": {"REGISTER": {"token": token}},
      "presetAvatars": []
    })
    return

  let user = app.db.findUserByPhone(phone)
  if user.len == 0:
    await ws.sendErr(req, AuthOpcode.int, userNotFoundError())
    return

  app.db.deleteAuthToken(token)
  let loginToken = generateRandomString(128)
  app.db.insertSessionToken(phone, loginToken, "WEB", "WebSocket", countryFromPhone(phone), nowUnixMs())
  await ws.sendOk(req, AuthOpcode.int, %*{
    "tokenAttrs": {"LOGIN": {"token": loginToken}},
    "profile": profileJson(user)
  })

proc handleAuthConfirm(app: AppContext, ws: WSSession, req: JsonNode): Future[void] {.async.} =
  let payload = reqPayload(req)
  let token = payload{"token"}.getStr("")
  let firstName = payload{"firstName"}.getStr("").strip()
  let lastName = payload{"lastName"}.getStr("").strip()
  if token.len == 0 or firstName.len == 0:
    await ws.sendErr(req, AuthConfirmOpcode.int, invalidPayloadError())
    return

  let stored = app.db.findAuthToken(token)
  if stored.len == 0 or rowString(stored, "state") != "verified":
    await ws.sendErr(req, AuthConfirmOpcode.int, codeExpiredError())
    return

  let phone = rowString(stored, "phone")
  if app.db.findUserByPhone(phone).len != 0:
    await ws.sendErr(req, AuthConfirmOpcode.int, invalidPayloadError())
    return

  let user = app.db.createOnemeUser(phone, firstName, lastName)
  app.db.deleteAuthToken(token)
  let loginToken = generateRandomString(128)
  app.db.insertSessionToken(phone, loginToken, "WEB", "WebSocket", countryFromPhone(phone), nowUnixMs())
  await ws.sendOk(req, AuthConfirmOpcode.int, %*{
    "userToken": rowInt64(user, "id"),
    "profile": profileJson(user),
    "tokenType": "REGISTER",
    "token": loginToken
  })

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
    "profile": profileJson(user),
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
    await ws.sendErr(req, CallsTokenOpcode.int, invalidTokenError())
    return
  let token = "openmax-call:" & $currentUserId & ":" & generateRandomString(64)
  app.calls.registerCallToken(token, currentUserId)
  await ws.sendOk(req, CallsTokenOpcode.int, %*{
    "token": token
  })

proc handleWsFrame(app: AppContext, ws: WSSession, req: JsonNode, state: WsConnectionState): Future[void] {.async.} =
  let opcode = reqInt(req, "opcode", 0)
  case uint16(opcode)
  of SessionInitOpcode:
    await handleSessionInit(ws, req)
  of PingOpcode:
    await ws.sendOk(req, PingOpcode.int, newJNull())
  of LogOpcode:
    await ws.sendOk(req, LogOpcode.int, newJNull())
  of AuthRequestOpcode:
    await handleAuthRequest(app, ws, req)
  of AuthOpcode:
    await handleAuth(app, ws, req)
  of AuthConfirmOpcode:
    await handleAuthConfirm(app, ws, req)
  of LoginOpcode:
    await handleLogin(app, ws, req, state)
  of LogoutOpcode:
    await handleLogout(app, ws, req, state)
  of CallsTokenOpcode:
    await handleCallsToken(app, ws, req, state.currentUserId)
  else:
    await ws.sendErr(req, opcode, notImplementedError())

proc handleOnemeWebSocket*(app: AppContext, ws: WSSession, peer: string): Future[void] {.async.} =
  let state = WsConnectionState(currentUserId: 0, currentSessionToken: "")
  safeInfo(&"[oneme/ws] connected peer={peer}")
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
      await handleWsFrame(app, ws, req, state)
  except WebSocketError as exc:
    # Some clients close the socket with a close payload that nim-websock rejects
    # while parsing the optional close reason. Treat that as a normal disconnect:
    # the application protocol has already finished and there is no server-side
    # action required.
    if exc.msg.contains("Invalid UTF8 sequence detected in close reason"):
      safeInfo(&"[oneme/ws] websocket close peer={peer}: invalid/empty close reason")
    else:
      safeInfo(&"[oneme/ws] websocket error peer={peer}: {exc.msg}")
  except CatchableError as exc:
    safeInfo(&"[oneme/ws] handler error peer={peer}: {exc.msg}")
  finally:
    safeInfo(&"[oneme/ws] disconnected peer={peer} user={state.currentUserId}")
