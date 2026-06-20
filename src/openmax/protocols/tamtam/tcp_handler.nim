import std/[logging, strformat, strutils, tables]
import chronos
import msgpack4nim
import ../../core/connection_context
import ../../core/opcodes
import ../../db/store
import ../../proto/mobile_frame
import ../../proto/mobile_rpc
import ../../proto/msgpack_codec
import ../errors
import ../auth_utils
import ../profile_payloads

type
  TamtamUserAgent = object
    deviceType: string
    appVersion: string
    osVersion: string
    timezone: string
    screen: string
    pushDeviceType: string
    locale: string
    deviceName: string
    deviceLocale: string

  TamtamHelloPayload = object
    userAgent: TamtamUserAgent
    deviceId: string

  TamtamPingPayload = object
    interactive: bool

  TamtamRequestCodePayload = object
    phone: string

  TamtamVerifyCodePayload = object
    verifyCode: string
    authTokenType: string
    token: string

  TamtamConfirmPayload = object
    token: string
    name: string
    tokenType: string
    deviceType: string
    deviceId: string

  TamtamLoginPayload = object
    token: string
    interactive: bool

  TamtamSessionInitResponse = object
    proxy: string
    `logs-enabled`: bool
    `proxy-domains`: seq[string]
    location: string
    `libh-enabled`: bool
    `phone-auto-complete-enabled`: bool

  TamtamAuthRequestResponse = object
    verifyToken: string
    retries: int
    codeDelay: int
    codeLength: int
    callDelay: int
    requestType: string

  TamtamTokenValue = object
    token: string

  TamtamTokenAttrsNew = object
    `NEW`: TamtamTokenValue

  TamtamTokenTypesNew = object
    `NEW`: string

  TamtamAuthNewResponse = object
    tokenAttrs: TamtamTokenAttrsNew
    tokenTypes: TamtamTokenTypesNew

  TamtamTokenAttrsAuth = object
    `AUTH`: TamtamTokenValue

  TamtamTokenTypesAuth = object
    `AUTH`: string

  TamtamAuthExistingResponse = object
    profile: TamtamContactProfile
    tokenAttrs: TamtamTokenAttrsAuth
    tokenTypes: TamtamTokenTypesAuth

  TamtamConfirmResponse = object
    userToken: int64
    profile: TamtamContactProfile
    tokenType: string
    token: string

  LoginConfigPayload = object
    hash: string

  TamtamLoginResponse = object
    profile: TamtamContactProfile
    token: string
    time: int64
    config: LoginConfigPayload

proc safeInfo(message: string) =
  try:
    info message
  except Exception:
    discard

proc validHello(payload: TamtamHelloPayload): bool =
  payload.userAgent.deviceType.len > 0 and
  payload.userAgent.appVersion.len > 0 and
  payload.userAgent.deviceName.len > 0

proc validRequestCode(payload: TamtamRequestCodePayload): bool =
  normalizePhoneNumber(payload.phone).len > 0

proc validVerifyCode(payload: TamtamVerifyCodePayload): bool =
  payload.verifyCode.len > 0 and payload.token.len > 0

proc validConfirm(payload: TamtamConfirmPayload): bool =
  payload.token.len > 0

proc validLogin(payload: TamtamLoginPayload): bool =
  payload.token.len > 0

proc deviceTypeOrDefault(ctx: ConnectionContext, payloadDeviceType: string): string =
  if payloadDeviceType.len > 0:
    payloadDeviceType
  elif ctx.deviceType.len > 0:
    ctx.deviceType
  else:
    "ANDROID"

proc deviceNameOrDefault(ctx: ConnectionContext): string =
  if ctx.deviceName.len > 0: ctx.deviceName else: "Unknown device"

proc handleSessionInit(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, TamtamHelloPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, SessionInitOpcode, invalidPayloadError())
      return

  if not validHello(payload):
    await transp.sendErrorResponse(frame, SessionInitOpcode, invalidPayloadError())
    return

  ctx.deviceType = payload.userAgent.deviceType
  ctx.deviceName = payload.userAgent.deviceName
  ctx.appVersion = payload.userAgent.appVersion

  let response = TamtamSessionInitResponse(
    proxy: "",
    `logs-enabled`: false,
    `proxy-domains`: @[],
    location: "RU",
    `libh-enabled`: false,
    `phone-auto-complete-enabled`: false
  )

  await transp.sendResponseObject(frame, CmdOk, SessionInitOpcode, response)

  safeInfo(
    &"[tamtam/tcp] session_init ok peer={ctx.peer} deviceType={ctx.deviceType} deviceName={ctx.deviceName} appVersion={ctx.appVersion}"
  )

proc handleAuthRequest(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, TamtamRequestCodePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AuthRequestOpcode, invalidPayloadError())
      return

  if not validRequestCode(payload):
    await transp.sendErrorResponse(frame, AuthRequestOpcode, invalidPayloadError())
    return

  let phone = normalizePhoneNumber(payload.phone)
  let existingUser = ctx.app.db.findUserByPhone(phone)
  let state = if existingUser.len == 0: "register" else: "started"
  let authToken = generateRandomString(128)
  let verifyCode = generateCode()
  let expires = nowUnix() + 300

  ctx.app.db.insertAuthToken(phone, authToken, verifyCode, expires, state)

  let response = TamtamAuthRequestResponse(
    verifyToken: authToken,
    retries: 5,
    codeDelay: 60,
    codeLength: 6,
    callDelay: 0,
    requestType: "SMS"
  )

  await transp.sendResponseObject(frame, CmdOk, AuthRequestOpcode, response)
  safeInfo(&"[tamtam/tcp] auth_request phone={phone} code={verifyCode} existing={not (existingUser.len == 0)}")

proc handleAuth(ctx: ConnectionContext,
                transp: StreamTransport,
                frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, TamtamVerifyCodePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AuthOpcode, invalidPayloadError())
      return

  if not validVerifyCode(payload):
    await transp.sendErrorResponse(frame, AuthOpcode, invalidPayloadError())
    return

  let stored = ctx.app.db.findAuthToken(payload.token)
  if stored.len == 0:
    await transp.sendErrorResponse(frame, AuthOpcode, codeExpiredError())
    return

  if rowString(stored, "code_hash") != payload.verifyCode:
    await transp.sendErrorResponse(frame, AuthOpcode, invalidCodeError())
    return

  let phone = rowString(stored, "phone")
  if rowString(stored, "state") == "register":
    ctx.app.db.updateAuthTokenState(payload.token, "verified")
    let response = TamtamAuthNewResponse(
      tokenAttrs: TamtamTokenAttrsNew(`NEW`: TamtamTokenValue(token: payload.token)),
      tokenTypes: TamtamTokenTypesNew(`NEW`: payload.token)
    )
    await transp.sendResponseObject(frame, CmdOk, AuthOpcode, response)
    return

  let user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    await transp.sendErrorResponse(frame, AuthOpcode, userNotFoundError())
    return

  ctx.app.db.updateAuthTokenState(payload.token, "verified")
  let response = TamtamAuthExistingResponse(
    profile: buildTamtamProfile(user),
    tokenAttrs: TamtamTokenAttrsAuth(`AUTH`: TamtamTokenValue(token: payload.token)),
    tokenTypes: TamtamTokenTypesAuth(`AUTH`: payload.token)
  )

  await transp.sendResponseObject(frame, CmdOk, AuthOpcode, response)

proc handleAuthConfirm(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, TamtamConfirmPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
      return

  if not validConfirm(payload):
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
    return

  let stored = ctx.app.db.findAuthToken(payload.token)
  if stored.len == 0:
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidTokenError())
    return

  let state = rowString(stored, "state")
  if state == "started" or state == "register":
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidTokenError())
    return

  let phone = rowString(stored, "phone")
  var user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    let trimmedName = payload.name.strip()
    if trimmedName.len == 0 or trimmedName.len > 59:
      await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
      return
    user = ctx.app.db.createTamtamUser(phone, trimmedName)

  ctx.app.db.deleteAuthToken(payload.token)

  let loginToken = generateRandomString(128)
  ctx.app.db.insertSessionToken(
    phone,
    loginToken,
    deviceTypeOrDefault(ctx, payload.deviceType),
    deviceNameOrDefault(ctx),
    "Localhost Federation",
    nowUnixMs()
  )

  let userId = rowInt64(user, "id")
  let response = TamtamConfirmResponse(
    userToken: userId,
    profile: buildTamtamProfile(user),
    tokenType: "LOGIN",
    token: loginToken
  )

  await transp.sendResponseObject(frame, CmdOk, AuthConfirmOpcode, response)
  safeInfo(&"[tamtam/tcp] auth_confirm finished phone={phone} userId={userId}")

proc handleLogin(ctx: ConnectionContext,
                 transp: StreamTransport,
                 frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, TamtamLoginPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, LoginOpcode, invalidPayloadError())
      return

  if not validLogin(payload):
    await transp.sendErrorResponse(frame, LoginOpcode, invalidPayloadError())
    return

  let sessionRow = ctx.app.db.findSessionToken(payload.token)
  if sessionRow.len == 0:
    await transp.sendErrorResponse(frame, LoginOpcode, invalidTokenError())
    return

  let phone = rowString(sessionRow, "phone")
  let user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    await transp.sendErrorResponse(frame, LoginOpcode, userNotFoundError())
    return

  let response = TamtamLoginResponse(
    profile: buildTamtamProfile(user),
    token: payload.token,
    time: nowUnixMs(),
    config: LoginConfigPayload(hash: "0")
  )

  await transp.sendResponseObject(frame, CmdOk, LoginOpcode, response)

proc handlePing(transp: StreamTransport,
                frame: MobileFrame): Future[void] {.async.} =
  if frame.payload.len > 0:
    try:
      discard unpackMapPayload(frame.payload, TamtamPingPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, PingOpcode, invalidPayloadError())
      return

  await transp.sendNilResponse(frame, CmdOk, PingOpcode)

proc handleLog(transp: StreamTransport,
               frame: MobileFrame): Future[void] {.async.} =
  await transp.sendNilResponse(frame, CmdOk, LogOpcode)

proc handleTcpFrame*(ctx: ConnectionContext,
                     transp: StreamTransport,
                     frame: MobileFrame): Future[void] {.async.} =
  safeInfo(
    &"[tamtam/tcp] frame from {ctx.peer}: ver={frame.header.ver} cmd={frame.header.cmd} seq={frame.header.seq} opcode={frame.header.opcode} comp={frame.header.compressionFlag} payload={frame.payload.len}B"
  )

  case frame.header.opcode
  of SessionInitOpcode:
    await handleSessionInit(ctx, transp, frame)
  of PingOpcode:
    await handlePing(transp, frame)
  of LogOpcode:
    await handleLog(transp, frame)
  of AuthRequestOpcode:
    await handleAuthRequest(ctx, transp, frame)
  of AuthOpcode:
    await handleAuth(ctx, transp, frame)
  of AuthConfirmOpcode:
    await handleAuthConfirm(ctx, transp, frame)
  of LoginOpcode:
    await handleLogin(ctx, transp, frame)
  else:
    await transp.sendErrorResponse(frame, frame.header.opcode, notImplementedError())
