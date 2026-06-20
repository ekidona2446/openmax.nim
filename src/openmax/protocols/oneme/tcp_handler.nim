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
  OnemeUserAgent = object
    deviceType: string
    appVersion: string
    osVersion: string
    timezone: string
    screen: string
    pushDeviceType: string
    locale: string
    deviceName: string
    deviceLocale: string

  OnemeHelloPayload = object
    clientSessionId: int64
    mt_instanceid: string
    userAgent: OnemeUserAgent
    deviceId: string

  OnemePingPayload = object
    interactive: bool

  OnemeRequestCodePayload = object
    phone: string
    `type`: string

  OnemeVerifyCodePayload = object
    verifyCode: string
    authTokenType: string
    token: string

  OnemeConfirmRegistrationPayload = object
    token: string
    firstName: string
    lastName: string
    tokenType: string

  OnemeLoginPayload = object
    token: string
    interactive: bool

  OnemeSessionInitResponse = object
    callsSeed: int64
    location: string
    `app-update-type`: int
    `reg-country-code`: seq[string]
    `phone-auto-complete-enabled`: bool
    `qr-auth-enabled`: bool
    lang: bool

  OnemeAuthRequestResponse = object
    token: string
    codeLength: int
    requestMaxDuration: int
    requestCountLeft: int
    altActionDuration: int

  OnemeTokenValue = object
    token: string

  OnemeTokenAttrsRegister = object
    `REGISTER`: OnemeTokenValue

  OnemeTokenAttrsLogin = object
    `LOGIN`: OnemeTokenValue

  OnemeAuthRegisterResponse = object
    tokenAttrs: OnemeTokenAttrsRegister
    presetAvatars: seq[string]

  OnemeAuthLoginResponse = object
    tokenAttrs: OnemeTokenAttrsLogin
    profile: OnemeProfilePayload

  OnemeConfirmRegistrationResponse = object
    userToken: int64
    profile: OnemeProfilePayload
    tokenType: string
    token: string

  LoginConfigPayload = object
    hash: string

  OnemeLoginResponse = object
    profile: OnemeProfilePayload
    token: string
    time: int64
    config: LoginConfigPayload

proc safeInfo(message: string) =
  try:
    info message
  except Exception:
    discard

proc validHello(payload: OnemeHelloPayload): bool =
  payload.userAgent.deviceType.len > 0 and
  payload.userAgent.appVersion.len > 0 and
  payload.userAgent.deviceName.len > 0 and
  payload.deviceId.len > 0

proc validRequestCode(payload: OnemeRequestCodePayload): bool =
  let normalized = normalizePhoneNumber(payload.phone)
  normalized.len > 0 and payload.`type` in ["START_AUTH", "RESEND"]

proc validVerifyCode(payload: OnemeVerifyCodePayload): bool =
  payload.verifyCode.len > 0 and payload.token.len > 0

proc validConfirmRegistration(payload: OnemeConfirmRegistrationPayload): bool =
  payload.token.len > 0 and payload.firstName.strip().len > 0 and
  payload.firstName.strip().len <= 59 and payload.lastName.strip().len <= 59

proc validLogin(payload: OnemeLoginPayload): bool =
  payload.token.len > 0

proc deviceTypeOrDefault(ctx: ConnectionContext): string =
  if ctx.deviceType.len > 0: ctx.deviceType else: "ANDROID"

proc deviceNameOrDefault(ctx: ConnectionContext): string =
  if ctx.deviceName.len > 0: ctx.deviceName else: "Unknown"

proc handleSessionInit(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeHelloPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, SessionInitOpcode, invalidPayloadError())
      return

  if not validHello(payload):
    await transp.sendErrorResponse(frame, SessionInitOpcode, invalidPayloadError())
    return

  ctx.deviceType = payload.userAgent.deviceType
  ctx.deviceName = payload.userAgent.deviceName
  ctx.appVersion = payload.userAgent.appVersion

  let response = OnemeSessionInitResponse(
    callsSeed: nowUnixMs(),
    location: "RU",
    `app-update-type`: 0,
    `reg-country-code`: @["RU"],
    `phone-auto-complete-enabled`: false,
    `qr-auth-enabled`: false,
    lang: true
  )

  await transp.sendResponseObject(frame, CmdOk, SessionInitOpcode, response)

  safeInfo(
    &"[oneme/tcp] session_init ok peer={ctx.peer} deviceType={ctx.deviceType} deviceName={ctx.deviceName} appVersion={ctx.appVersion}"
  )

proc handleAuthRequest(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeRequestCodePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AuthRequestOpcode, invalidPayloadError())
      return

  if not validRequestCode(payload):
    await transp.sendErrorResponse(frame, AuthRequestOpcode, invalidPayloadError())
    return

  let phone = normalizePhoneNumber(payload.phone)
  let existingUser = ctx.app.db.findUserByPhone(phone)
  let state = if existingUser.len == 0: "register" else: ""
  let authToken = generateRandomString(96)
  let verifyCode = generateCode()
  let expires = nowUnix() + 300

  ctx.app.db.insertAuthToken(phone, authToken, verifyCode, expires, state)

  let response = OnemeAuthRequestResponse(
    token: authToken,
    codeLength: 6,
    requestMaxDuration: 60000,
    requestCountLeft: 10,
    altActionDuration: 60000
  )

  await transp.sendResponseObject(frame, CmdOk, AuthRequestOpcode, response)
  safeInfo(&"[oneme/tcp] auth_request phone={phone} code={verifyCode} existing={not (existingUser.len == 0)}")

proc handleAuth(ctx: ConnectionContext,
                transp: StreamTransport,
                frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeVerifyCodePayload)
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
    let response = OnemeAuthRegisterResponse(
      tokenAttrs: OnemeTokenAttrsRegister(`REGISTER`: OnemeTokenValue(token: payload.token)),
      presetAvatars: @[]
    )
    await transp.sendResponseObject(frame, CmdOk, AuthOpcode, response)
    return

  let user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    await transp.sendErrorResponse(frame, AuthOpcode, userNotFoundError())
    return

  ctx.app.db.deleteAuthToken(payload.token)

  let loginToken = generateRandomString(128)
  ctx.app.db.insertSessionToken(
    phone,
    loginToken,
    deviceTypeOrDefault(ctx),
    deviceNameOrDefault(ctx),
    "Localhost Federation",
    nowUnixMs()
  )

  let response = OnemeAuthLoginResponse(
    tokenAttrs: OnemeTokenAttrsLogin(`LOGIN`: OnemeTokenValue(token: loginToken)),
    profile: buildOnemeProfile(user)
  )

  await transp.sendResponseObject(frame, CmdOk, AuthOpcode, response)

proc handleAuthConfirm(ctx: ConnectionContext,
                       transp: StreamTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeConfirmRegistrationPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
      return

  if not validConfirmRegistration(payload):
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
    return

  let stored = ctx.app.db.findAuthToken(payload.token)
  if stored.len == 0 or rowString(stored, "state") != "verified":
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, codeExpiredError())
    return

  let phone = rowString(stored, "phone")
  if ctx.app.db.findUserByPhone(phone).len != 0:
    await transp.sendErrorResponse(frame, AuthConfirmOpcode, invalidPayloadError())
    return

  let user = ctx.app.db.createOnemeUser(phone, payload.firstName.strip(), payload.lastName.strip())
  ctx.app.db.deleteAuthToken(payload.token)

  let loginToken = generateRandomString(128)
  ctx.app.db.insertSessionToken(
    phone,
    loginToken,
    deviceTypeOrDefault(ctx),
    deviceNameOrDefault(ctx),
    "Localhost Federation",
    nowUnixMs()
  )

  let userId = rowInt64(user, "id")
  let response = OnemeConfirmRegistrationResponse(
    userToken: userId,
    profile: buildOnemeProfile(user),
    tokenType: "LOGIN",
    token: loginToken
  )

  await transp.sendResponseObject(frame, CmdOk, AuthConfirmOpcode, response)
  safeInfo(&"[oneme/tcp] auth_confirm registered phone={phone} userId={userId}")

proc handleLogin(ctx: ConnectionContext,
                 transp: StreamTransport,
                 frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeLoginPayload)
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

  let response = OnemeLoginResponse(
    profile: buildOnemeProfile(user),
    token: payload.token,
    time: nowUnixMs(),
    config: LoginConfigPayload(hash: "0")
  )

  await transp.sendResponseObject(frame, CmdOk, LoginOpcode, response)

proc handlePing(transp: StreamTransport,
                frame: MobileFrame): Future[void] {.async.} =
  if frame.payload.len > 0:
    try:
      discard unpackMapPayload(frame.payload, OnemePingPayload)
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
    &"[oneme/tcp] frame from {ctx.peer}: ver={frame.header.ver} cmd={frame.header.cmd} seq={frame.header.seq} opcode={frame.header.opcode} comp={frame.header.compressionFlag} payload={frame.payload.len}B"
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
