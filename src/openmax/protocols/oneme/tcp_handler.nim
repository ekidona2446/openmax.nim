import std/[logging, strformat, strutils, tables, json]
import chronos
import msgpack4nim
import ../../core/connection_context
import ../../core/app_context
import ../../core/calls_state
import ../../core/opcodes
import ../../crypto/sha256
import ../../db/store
import ../../db/sqlite_abi
import ../../proto/mobile_frame
import ../../proto/mobile_rpc
import ../../proto/msgpack_codec
import ../errors
import ../auth_utils
import ../profile_payloads
import ../server_config_data
import ../static_data
import ../uploads_http

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

  OnemeSessionInfo = object
    id: string
    deviceId: string
    current: bool
    userAgent: string
    appVersion: string
    deviceName: string
    deviceType: string
    platform: string
    ip: string
    location: string
    created: int64
    updated: int64
    lastActivity: int64

  OnemeSessionsInfoResponse = object
    sessions: seq[OnemeSessionInfo]

  OnemeFolderPayload = object
    id: string
    title: string
    filters: seq[string]
    updateTime: int64
    options: seq[string]
    sourceId: int
    `include`: seq[int64]

  OnemeFoldersGetResponse = object
    folderSync: int64
    folders: seq[OnemeFolderPayload]
    foldersOrder: seq[string]
    allFilterExcludeFolders: seq[string]

  OnemeChatsListResponse = object
    chats: seq[string]

  OnemeContactByPhonePayload = object
    phone: string

  OnemeUpdateProfilePayload = object
    description: string
    firstName: string
    lastName: string

  OnemeAssetsGetPayload = object
    `type`: string
    count: int
    query: string

  OnemeAssetsGetByIdsPayload = object
    `type`: string
    ids: seq[string]

  OnemeContactAddByPhonePayload = object
    phone: string
    firstName: string
    lastName: string

  OnemeContactPresencePayload = object
    contactIds: seq[int64]

  OnemeContactListPayload = object
    status: string
    count: int

  OnemeChatSubscribePayload = object
    chatId: int64
    subscribe: bool

  OnemeFullContactUpdatePayload = object
    action: string
    contactId: int64
    firstName: string
    lastName: string

  OnemeContactInfoPayload = object
    contactIds: seq[int64]

  OnemeContactUpdatePayload = object
    contactId: int64
    action: string

  OnemeTypingPayload = object
    chatId: int64
    `type`: string

  OnemeTypingEvent = object
    chatId: int64
    userId: int64

  OnemeEditMessagePayload = object
    chatId: int64
    messageId: int64
    text: string
    elements: seq[string]
    attachments: seq[string]

  OnemeMessageItemResponse = object
    message: OnemeMessagePayload

  OnemeDeleteMessagePayload = object
    chatId: int64
    messageIds: seq[int64]
    forMe: bool

  OnemeDeleteEvent = object
    chatId: int64
    messageIds: seq[int64]
    ttl: bool

  OnemeReadMessagePayload = object
    `type`: string
    chatId: int64
    messageId: int64
    mark: int64

  OnemeReadStateResponse = object
    unread: int
    mark: int64

  OnemeReadEvent = object
    setAsUnread: bool
    chatId: int64
    userId: int64
    mark: int64

  OnemeContactsResponse = object
    contacts: seq[OnemeContactProfile]

  OnemeContactInfoByPhoneResponse = object
    contact: OnemeContactProfile

  OnemeCallTokenResponse = object
    token: string

  OnemeReactionInfoPayload = object
    totalCount: int
    counters: seq[string]

  OnemeMessagePayload = object
    id: int64
    chatId: int64
    sender: int64
    text: string
    time: int64
    `type`: string
    cid: int64
    attaches: seq[string]
    elements: seq[string]
    reactionInfo: OnemeReactionInfoPayload

  OnemeSendMessageInner = object
    text: string
    cid: int64
    elements: seq[string]
    attaches: seq[string]

  OnemeSendMessagePayload = object
    chatId: int64
    userId: int64
    message: OnemeSendMessageInner
    notify: bool

  OnemeMessagesListResponse = object
    messages: seq[OnemeMessagePayload]

  OnemeGetMessagesPayload = object
    chatId: int64
    messageIds: seq[int64]

  OnemeChatInfoPayload = object
    chatIds: seq[int64]

  OnemeChatHistoryPayload = object
    chatId: int64
    forward: int
    backward: int
    backwardTime: int64
    forwardTime: int64
    getChat: bool
    `from`: int64
    itemType: string
    getMessages: bool
    interactive: bool

  OnemeChatPayload = object
    id: int64
    `type`: string
    status: string
    owner: int64
    participants: Table[string, int]
    lastMessage: OnemeMessagePayload
    lastEventTime: int64
    lastDelayedUpdateTime: int64
    lastFireDelayedErrorTime: int64
    created: int64
    joinTime: int64
    modified: int64

  OnemeChatsResponse = object
    chats: seq[OnemeChatPayload]

proc safeInfo(message: string) =
  try:
    info message
  except Exception:
    discard

proc jsonInt64(node: JsonNode, key: string, defaultValue = 0'i64): int64 =
  if node.kind == JObject and node.hasKey(key):
    try: return node[key].getBiggestInt().int64
    except CatchableError: discard
  defaultValue

proc jsonObj(node: JsonNode, key: string): JsonNode =
  if node.kind == JObject and node.hasKey(key): node[key] else: newJObject()

proc jsonArrayOrEmpty(node: JsonNode, key: string): JsonNode =
  if node.kind == JObject and node.hasKey(key) and node[key].kind == JArray:
    node[key]
  else:
    newJArray()

proc emptyReactionInfo(): OnemeReactionInfoPayload =
  OnemeReactionInfoPayload(totalCount: 0, counters: @[])

proc emptyMessage(chatId = 0'i64): OnemeMessagePayload =
  OnemeMessagePayload(
    id: 0,
    chatId: chatId,
    sender: 0,
    text: "",
    time: 0,
    `type`: "USER",
    cid: 0,
    attaches: @[],
    elements: @[],
    reactionInfo: emptyReactionInfo()
  )

proc messageFromRow(row: DbRow): OnemeMessagePayload =
  if row.len == 0:
    return emptyMessage()

  OnemeMessagePayload(
    id: rowInt64(row, "id"),
    chatId: rowInt64(row, "chat_id"),
    sender: rowInt64(row, "sender"),
    text: rowString(row, "text"),
    time: rowInt64(row, "time"),
    `type`: rowString(row, "type"),
    cid: rowInt64(row, "cid"),
    attaches: @[],
    elements: @[],
    reactionInfo: emptyReactionInfo()
  )


proc jsonFromStored(value: string, fallback: JsonNode): JsonNode =
  try:
    parseJson(value)
  except CatchableError:
    fallback


proc normalizeAttach(a: JsonNode): JsonNode =
  if a.kind != JObject:
    return a
  let typ = a{"_type"}.getStr(a{"type"}.getStr(""))
  case typ
  of "FILE":
    result = copy(a)
    if not result.hasKey("_type"): result["_type"] = %"FILE"
    if not result.hasKey("name"): result["name"] = %"file"
    if not result.hasKey("size"): result["size"] = %0
    if not result.hasKey("token"): result["token"] = %""
  of "PHOTO":
    result = copy(a)
    if not result.hasKey("_type"): result["_type"] = %"PHOTO"
    if not result.hasKey("baseUrl"): result["baseUrl"] = %""
    if not result.hasKey("height"): result["height"] = %0
    if not result.hasKey("width"): result["width"] = %0
    if not result.hasKey("photoId"): result["photoId"] = %0
    if not result.hasKey("photoToken"):
      result["photoToken"] = %a{"photo_token"}.getStr("")
  of "VIDEO":
    result = copy(a)
    if not result.hasKey("_type"): result["_type"] = %"VIDEO"
    if not result.hasKey("height"): result["height"] = %0
    if not result.hasKey("width"): result["width"] = %0
    if not result.hasKey("duration"): result["duration"] = newJNull()
    if not result.hasKey("previewData"): result["previewData"] = %""
    if not result.hasKey("thumbnail"): result["thumbnail"] = %""
    if not result.hasKey("token"): result["token"] = %""
    if not result.hasKey("videoType"): result["videoType"] = %0
  else:
    result = a

proc normalizeAttaches(node: JsonNode): JsonNode =
  result = newJArray()
  if node.kind != JArray:
    return
  for item in node.items:
    result.add normalizeAttach(item)

proc messageJsonFromRow(row: DbRow): JsonNode =
  if row.len == 0:
    return %*{
      "id": 0, "chatId": 0, "sender": 0, "text": "", "time": 0,
      "type": "USER", "cid": 0, "attaches": [], "elements": [],
      "reactionInfo": {"totalCount": 0, "counters": []}
    }

  %*{
    "id": rowInt64(row, "id"),
    "chatId": rowInt64(row, "chat_id"),
    "sender": rowInt64(row, "sender"),
    "text": rowString(row, "text"),
    "time": rowInt64(row, "time"),
    "type": rowString(row, "type"),
    "cid": rowInt64(row, "cid"),
    "attaches": normalizeAttaches(jsonFromStored(rowString(row, "attaches"), newJArray())),
    "elements": jsonFromStored(rowString(row, "elements"), newJArray()),
    "reactionInfo": {"totalCount": 0, "counters": []}
  }

proc participantsTable(ids: openArray[int64]): Table[string, int] =
  result = initTable[string, int]()
  for id in ids:
    result[$id] = 0

proc chatFromRow(ctx: ConnectionContext, row: DbRow): OnemeChatPayload =
  let chatId = rowInt64(row, "id")
  let participants = ctx.app.db.participantsOfChat(chatId)
  let last = messageFromRow(ctx.app.db.lastMessageForChat(chatId))
  let lastTime = if last.id == 0: 0'i64 else: last.time

  OnemeChatPayload(
    id: chatId,
    `type`: rowString(row, "type"),
    status: "ACTIVE",
    owner: rowInt64(row, "owner"),
    participants: participantsTable(participants),
    lastMessage: if last.id == 0: emptyMessage(chatId) else: last,
    lastEventTime: lastTime,
    lastDelayedUpdateTime: 0,
    lastFireDelayedErrorTime: 0,
    created: 1,
    joinTime: 1,
    modified: lastTime
  )

proc messageToJson(message: OnemeMessagePayload, status = ""): JsonNode =
  result = %*{
    "id": message.id,
    "chatId": message.chatId,
    "sender": message.sender,
    "text": message.text,
    "time": message.time,
    "type": message.`type`,
    "cid": message.cid,
    "attaches": [],
    "elements": [],
    "reactionInfo": {
      "totalCount": 0,
      "counters": []
    }
  }
  if status.len > 0:
    result["status"] = %status

proc participantsToJson(ids: openArray[int64]): JsonNode =
  result = newJObject()
  for id in ids:
    result[$id] = %0

proc chatToJson(ctx: ConnectionContext, chat: OnemeChatPayload): JsonNode =
  let participants = ctx.app.db.participantsOfChat(chat.id)
  %*{
    "id": chat.id,
    "type": chat.`type`,
    "status": chat.status,
    "owner": chat.owner,
    "participants": participantsToJson(participants),
    "lastMessage": messageToJson(chat.lastMessage),
    "lastEventTime": chat.lastEventTime,
    "lastDelayedUpdateTime": chat.lastDelayedUpdateTime,
    "lastFireDelayedErrorTime": chat.lastFireDelayedErrorTime,
    "created": chat.created,
    "joinTime": chat.joinTime,
    "modified": chat.modified
  }

proc chatsResponseJson(ctx: ConnectionContext, chats: openArray[OnemeChatPayload]): JsonNode =
  result = newJObject()
  result["chats"] = newJArray()
  for chat in chats:
    result["chats"].add chatToJson(ctx, chat)

proc requireLoggedIn(ctx: ConnectionContext,
                     transp: MobileTransport,
                     frame: MobileFrame,
                     opcode: uint16): Future[bool] {.async.} =
  if ctx.currentUserId == 0:
    await transp.sendErrorResponse(frame, opcode, invalidTokenError())
    return false
  true

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
                       transp: MobileTransport,
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
  let country = countryFromUserAgent(payload.userAgent.locale, payload.userAgent.deviceLocale, "RU")

  let response = OnemeSessionInitResponse(
    callsSeed: nowUnixMs(),
    location: country,
    `app-update-type`: 0,
    `reg-country-code`: @[country],
    `phone-auto-complete-enabled`: false,
    `qr-auth-enabled`: false,
    lang: true
  )

  await transp.sendResponseObject(frame, CmdOk, SessionInitOpcode, response)

  safeInfo(
    &"[oneme/tcp] session_init ok peer={ctx.peer} deviceType={ctx.deviceType} deviceName={ctx.deviceName} appVersion={ctx.appVersion}"
  )

proc handleAuthRequest(ctx: ConnectionContext,
                       transp: MobileTransport,
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
  let expires = store.nowUnix() + 300

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
                transp: MobileTransport,
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

  if rowString(stored, "code_hash") != sha256Hex(payload.verifyCode):
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
    countryFromPhone(phone),
    nowUnixMs()
  )

  let response = OnemeAuthLoginResponse(
    tokenAttrs: OnemeTokenAttrsLogin(`LOGIN`: OnemeTokenValue(token: loginToken)),
    profile: buildOnemeProfile(user)
  )

  await transp.sendResponseObject(frame, CmdOk, AuthOpcode, response)

proc handleAuthConfirm(ctx: ConnectionContext,
                       transp: MobileTransport,
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
    countryFromPhone(phone),
    nowUnixMs()
  )

  let userId = rowInt64(user, "id")
  let response = OnemeConfirmRegistrationResponse(
    userToken: userId,
    profile: buildOnemeProfile(user),
    # PyMax validates this field against AuthType, whose values do not include LOGIN.
    # The actual login credential is still returned in `token` and is used by the client.
    tokenType: "REGISTER",
    token: loginToken
  )

  await transp.sendResponseObject(frame, CmdOk, AuthConfirmOpcode, response)
  safeInfo(&"[oneme/tcp] auth_confirm registered phone={phone} userId={userId}")

proc handleLogin(ctx: ConnectionContext,
                 transp: MobileTransport,
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

  ctx.currentPhone = phone
  ctx.currentUserId = rowInt64(user, "id")
  ctx.currentSessionToken = payload.token
  ctx.app.attachClient(ctx.currentUserId, transp)

  let response = OnemeLoginResponse(
    profile: buildOnemeProfile(user),
    token: payload.token,
    time: nowUnixMs(),
    config: LoginConfigPayload(hash: "0")
  )

  await transp.sendResponseObject(frame, CmdOk, LoginOpcode, response)


proc handleLogout(ctx: ConnectionContext,
                  transp: MobileTransport,
                  frame: MobileFrame): Future[void] {.async.} =
  if ctx.currentSessionToken.len > 0:
    ctx.app.db.deleteSessionToken(ctx.currentSessionToken)
  if ctx.currentUserId != 0:
    ctx.app.detachClient(ctx.currentUserId, transp)
  ctx.currentPhone = ""
  ctx.currentUserId = 0
  ctx.currentSessionToken = ""
  await transp.sendNilResponse(frame, CmdOk, LogoutOpcode)

proc handlePing(transp: MobileTransport,
                frame: MobileFrame): Future[void] {.async.} =
  if frame.payload.len > 0:
    try:
      discard unpackMapPayload(frame.payload, OnemePingPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, PingOpcode, invalidPayloadError())
      return

  await transp.sendNilResponse(frame, CmdOk, PingOpcode)

proc handleLog(transp: MobileTransport,
               frame: MobileFrame): Future[void] {.async.} =
  await transp.sendNilResponse(frame, CmdOk, LogOpcode)


proc handleConfig(ctx: ConnectionContext,
                  transp: MobileTransport,
                  frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ConfigOpcode):
    return

  let payload =
    try:
      unpackJsonPayload(frame.payload)
    except MsgPackCodecError:
      newJObject()

  if payload.kind == JObject and payload.hasKey("pushToken"):
    ctx.app.db.updateSessionPushToken(ctx.currentPhone, ctx.currentSessionToken, payload{"pushToken"}.getStr(""))

  let userData = ctx.app.db.findUserDataByPhone(ctx.currentPhone)
  var userConfig =
    try:
      parseJson(rowString(userData, "user_config"))
    except CatchableError:
      parseJson(DefaultUserSettingsJson)

  # Privacy-settings write path (ported from main.py update_config): merge the
  # provided `settings.user` keys into the stored config and persist it.
  if payload.kind == JObject and payload.hasKey("settings"):
    let settings = payload["settings"]
    if settings.kind == JObject and settings.hasKey("user") and settings["user"].kind == JObject:
      if userConfig.kind != JObject:
        userConfig = parseJson(DefaultUserSettingsJson)
      for key, value in settings["user"]:
        if userConfig.hasKey(key):
          userConfig[key] = value
      ctx.app.db.updateUserConfig(ctx.currentPhone, $userConfig)

  let response = %*{
    "hash": "0",
    "server": parseJson(OnemeServerConfigJson),
    "user": userConfig
  }
  await transp.sendResponseBytes(frame, CmdOk, ConfigOpcode, packJsonPayload(response))

proc handleSessionsInfo(ctx: ConnectionContext,
                        transp: MobileTransport,
                        frame: MobileFrame): Future[void] {.async.} =
  let now = nowUnixMs()
  var sessions: seq[OnemeSessionInfo] = @[]

  if ctx.currentSessionToken.len > 0:
    sessions.add OnemeSessionInfo(
      id: ctx.currentSessionToken,
      deviceId: "",
      current: true,
      userAgent: "MAX " & deviceTypeOrDefault(ctx),
      appVersion: ctx.appVersion,
      deviceName: deviceNameOrDefault(ctx),
      deviceType: deviceTypeOrDefault(ctx),
      platform: deviceTypeOrDefault(ctx),
      ip: ctx.peer,
      location: countryFromPhone(ctx.currentPhone),
      created: now,
      updated: now,
      lastActivity: now
    )

  await transp.sendResponseObject(
    frame,
    CmdOk,
    SessionsInfoOpcode,
    OnemeSessionsInfoResponse(sessions: sessions)
  )

proc handleFoldersGet(ctx: ConnectionContext,
                      transp: MobileTransport,
                      frame: MobileFrame): Future[void] {.async.} =
  ## FOLDERS_GET (272): sync folders from the DB. Ported from folders.py.
  if not await requireLoggedIn(ctx, transp, frame, FoldersGetOpcode):
    return

  let phone = normalizePhone(ctx.currentPhone)
  var folders = newJArray()
  var order = newJArray()
  for row in ctx.app.db.foldersForPhone(phone):
    let id = rowString(row, "id")
    folders.add %*{
      "id": id,
      "title": rowString(row, "title"),
      "filters": jsonFromStored(rowString(row, "filters"), newJArray()),
      "include": jsonFromStored(rowString(row, "include"), newJArray()),
      "updateTime": rowInt64(row, "update_time"),
      "options": jsonFromStored(rowString(row, "options"), newJArray()),
      "sourceId": rowInt64(row, "source_id").int
    }
    order.add %id

  let response = %*{
    "folderSync": nowUnixMs(),
    "folders": folders,
    "foldersOrder": order,
    "allFilterExcludeFolders": []
  }
  await transp.sendResponseBytes(frame, CmdOk, FoldersGetOpcode, packJsonPayload(response))

proc handleChatsList(ctx: ConnectionContext,
                     transp: MobileTransport,
                     frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ChatsListOpcode):
    return

  var chats: seq[OnemeChatPayload] = @[]
  for row in ctx.app.db.chatsForUser(ctx.currentUserId):
    chats.add chatFromRow(ctx, row)

  await transp.sendResponseBytes(frame, CmdOk, ChatsListOpcode, packJsonPayload(chatsResponseJson(ctx, chats)))

proc handleChatInfo(ctx: ConnectionContext,
                    transp: MobileTransport,
                    frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ChatInfoOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeChatInfoPayload)
    except MsgPackCodecError:
      # PyMax's ChatInfo payload has chatIds; this fallback keeps old empty payloads harmless.
      await transp.sendResponseBytes(frame, CmdOk, ChatInfoOpcode, packJsonPayload(chatsResponseJson(ctx, newSeq[OnemeChatPayload]())))
      return

  var chats: seq[OnemeChatPayload] = @[]
  for chatId in payload.chatIds:
    let storageChatId = if chatId == 0: ctx.currentUserId else: chatId
    let row = ctx.app.db.findChatById(storageChatId)
    if row.len != 0 and ctx.currentUserId in ctx.app.db.participantsOfChat(storageChatId):
      chats.add chatFromRow(ctx, row)

  await transp.sendResponseBytes(frame, CmdOk, ChatInfoOpcode, packJsonPayload(chatsResponseJson(ctx, chats)))

proc storageChatIdFor(ctx: ConnectionContext, requestedChatId, userId: int64): int64 =
  if requestedChatId == 0:
    ctx.currentUserId
  elif requestedChatId != 0:
    requestedChatId
  elif userId != 0:
    ctx.currentUserId xor userId
  else:
    ctx.currentUserId

proc handleSendMessage(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, MsgSendOpcode):
    return

  let payload =
    try:
      unpackJsonPayload(frame.payload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, MsgSendOpcode, invalidPayloadError())
      return

  let message = payload.jsonObj("message")
  let text = message{"text"}.getStr("")
  let attachesNode = normalizeAttaches(message.jsonArrayOrEmpty("attaches"))
  let elementsNode = message.jsonArrayOrEmpty("elements")
  if text.len == 0 and attachesNode.len == 0:
    await transp.sendErrorResponse(frame, MsgSendOpcode, invalidPayloadError())
    return

  let requestedChatId = payload.jsonInt64("chatId")
  let targetUserId = payload.jsonInt64("userId")
  let chatId = storageChatIdFor(ctx, requestedChatId, targetUserId)
  if ctx.app.db.findChatById(chatId).len == 0:
    if chatId == ctx.currentUserId:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId])
    elif targetUserId != 0:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId, targetUserId])
    else:
      await transp.sendErrorResponse(frame, MsgSendOpcode, notImplementedError())
      return

  let participants = ctx.app.db.participantsOfChat(chatId)
  if ctx.currentUserId notin participants:
    await transp.sendErrorResponse(frame, MsgSendOpcode, invalidTokenError())
    return

  # In a DIALOG, refuse to deliver if the recipient has blocked the sender
  # (ported from messages.py: tools.contact_is_blocked check).
  let chatRow = ctx.app.db.findChatById(chatId)
  if rowString(chatRow, "type") == "DIALOG":
    for other in participants:
      if other != ctx.currentUserId and ctx.app.db.contactIsBlocked(other, ctx.currentUserId):
        await transp.sendErrorResponse(frame, MsgSendOpcode, contactBlockedError())
        return

  let row = ctx.app.db.insertMessage(
    chatId,
    ctx.currentUserId,
    message.jsonInt64("cid"),
    text,
    $attachesNode,
    $elementsNode,
    "USER",
    nowUnixMs()
  )

  let response = messageJsonFromRow(row)
  await transp.sendResponseBytes(frame, CmdOk, MsgSendOpcode, packJsonPayload(response))

  let eventBytes = packJsonPayload(response)
  let msgId = rowInt64(row, "id")
  for participant in participants:
    for client in ctx.app.transportsForUser(participant):
      try:
        await client.sendResponseBytes(frame, 0'u8, NotifMessageOpcode, eventBytes)
      except CatchableError as exc:
        safeInfo(&"[oneme/tcp] failed to fan-out message id={msgId} to user={participant}: {exc.msg}")

proc handleEditMessage(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, MsgEditOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeEditMessagePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, MsgEditOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  let participants = ctx.app.db.participantsOfChat(chatId)
  if ctx.currentUserId notin participants:
    await transp.sendErrorResponse(frame, MsgEditOpcode, invalidTokenError())
    return

  let row = ctx.app.db.updateMessage(chatId, payload.messageId, payload.text, "[]", "[]")
  if row.len == 0:
    await transp.sendErrorResponse(frame, MsgEditOpcode, notImplementedError())
    return

  let message = messageFromRow(row)
  await transp.sendResponseObject(frame, CmdOk, MsgEditOpcode, OnemeMessageItemResponse(message: message))

  for participant in participants:
    for client in ctx.app.transportsForUser(participant):
      try:
        await client.sendResponseBytes(frame, 0'u8, MsgEditOpcode, packJsonPayload(messageToJson(message, "EDITED")))
      except CatchableError as exc:
        safeInfo(&"[oneme/tcp] failed to fan-out edit id={message.id} to user={participant}: {exc.msg}")

proc handleDeleteMessages(ctx: ConnectionContext,
                          transp: MobileTransport,
                          frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, MsgDeleteOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeDeleteMessagePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, MsgDeleteOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  let participants = ctx.app.db.participantsOfChat(chatId)
  if ctx.currentUserId notin participants:
    await transp.sendErrorResponse(frame, MsgDeleteOpcode, invalidTokenError())
    return

  if not payload.forMe:
    ctx.app.db.deleteMessages(chatId, payload.messageIds)

  await transp.sendNilResponse(frame, CmdOk, MsgDeleteOpcode)

  let eventPayload = OnemeDeleteEvent(chatId: chatId, messageIds: payload.messageIds, ttl: false)
  for participant in participants:
    for client in ctx.app.transportsForUser(participant):
      try:
        await client.sendResponseObject(frame, 0'u8, NotifMsgDeleteOpcode, eventPayload)
      except CatchableError as exc:
        safeInfo(&"[oneme/tcp] failed to fan-out delete chat={chatId} to user={participant}: {exc.msg}")

proc handleChatMark(ctx: ConnectionContext,
                    transp: MobileTransport,
                    frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ChatMarkOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeReadMessagePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ChatMarkOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  let participants = ctx.app.db.participantsOfChat(chatId)
  if ctx.currentUserId notin participants:
    await transp.sendErrorResponse(frame, ChatMarkOpcode, invalidTokenError())
    return

  let mark = if payload.mark > 0: payload.mark else: nowUnixMs()
  await transp.sendResponseObject(frame, CmdOk, ChatMarkOpcode, OnemeReadStateResponse(unread: 0, mark: mark))

  let eventPayload = OnemeReadEvent(setAsUnread: false, chatId: chatId, userId: ctx.currentUserId, mark: mark)
  for participant in participants:
    if participant == ctx.currentUserId:
      continue
    for client in ctx.app.transportsForUser(participant):
      try:
        await client.sendResponseObject(frame, 0'u8, NotifMarkOpcode, eventPayload)
      except CatchableError as exc:
        safeInfo(&"[oneme/tcp] failed to fan-out mark chat={chatId} to user={participant}: {exc.msg}")

proc handleSync(ctx: ConnectionContext,
                transp: MobileTransport,
                frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, SyncOpcode):
    return

  var contacts: seq[OnemeContactProfile] = @[]
  let payload =
    try:
      unpackJsonPayload(frame.payload)
    except MsgPackCodecError:
      newJObject()

  if payload.kind == JObject and payload.hasKey("contactList") and payload["contactList"].kind == JObject:
    for phone, _ in payload["contactList"]:
      let user = ctx.app.db.findUserByPhone(normalizePhoneNumber(phone))
      if user.len != 0:
        ctx.app.db.addContact(ctx.currentUserId, rowInt64(user, "id"))
        contacts.add buildOnemeProfile(user).contact
  else:
    for userId in ctx.app.db.contactIdsForUser(ctx.currentUserId):
      let user = ctx.app.db.findUserById(userId)
      if user.len != 0:
        contacts.add buildOnemeProfile(user).contact

  await transp.sendResponseObject(frame, CmdOk, SyncOpcode, OnemeContactsResponse(contacts: contacts))

proc handleTyping(ctx: ConnectionContext,
                  transp: MobileTransport,
                  frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, MsgTypingOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeTypingPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, MsgTypingOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  let participants = ctx.app.db.participantsOfChat(chatId)
  if ctx.currentUserId notin participants:
    await transp.sendErrorResponse(frame, MsgTypingOpcode, invalidTokenError())
    return

  await transp.sendNilResponse(frame, CmdOk, MsgTypingOpcode)

  let eventPayload = OnemeTypingEvent(chatId: chatId, userId: ctx.currentUserId)
  for participant in participants:
    if participant == ctx.currentUserId:
      continue
    for client in ctx.app.transportsForUser(participant):
      try:
        await client.sendResponseObject(frame, 0'u8, NotifTypingOpcode, eventPayload)
      except CatchableError as exc:
        safeInfo(&"[oneme/tcp] failed to fan-out typing to user={participant}: {exc.msg}")

proc handleChatHistory(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ChatHistoryOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeChatHistoryPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ChatHistoryOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  if ctx.app.db.findChatById(chatId).len == 0 or ctx.currentUserId notin ctx.app.db.participantsOfChat(chatId):
    await transp.sendResponseBytes(frame, CmdOk, ChatHistoryOpcode, packJsonPayload(%*{"messages": []}))
    return

  let limit = max(1, max(payload.backward, payload.forward))
  var messages = newJArray()
  for row in ctx.app.db.messagesForChat(chatId, limit):
    messages.add messageJsonFromRow(row)

  await transp.sendResponseBytes(frame, CmdOk, ChatHistoryOpcode, packJsonPayload(%*{"messages": messages}))

proc handleGetMessages(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, MsgGetOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeGetMessagesPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, MsgGetOpcode, invalidPayloadError())
      return

  let chatId = if payload.chatId == 0: ctx.currentUserId else: payload.chatId
  var messages = newJArray()
  if ctx.currentUserId in ctx.app.db.participantsOfChat(chatId):
    for row in ctx.app.db.messagesByIds(chatId, payload.messageIds):
      messages.add messageJsonFromRow(row)

  await transp.sendResponseBytes(frame, CmdOk, MsgGetOpcode, packJsonPayload(%*{"messages": messages}))


proc handleUploadRequest(ctx: ConnectionContext,
                         transp: MobileTransport,
                         frame: MobileFrame,
                         opcode: uint16,
                         kind: string): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, opcode):
    return
  let payload = ctx.app.uploadRequestPayload("oneme", kind, ctx.currentUserId)
  safeInfo(&"[oneme/tcp] upload request kind={kind} payload={$payload}")
  await transp.sendResponseBytes(frame, CmdOk, opcode, packJsonPayload(payload))

proc handleCallsToken(ctx: ConnectionContext,
                      transp: MobileTransport,
                      frame: MobileFrame): Future[void] {.async.} =
  if ctx.currentUserId == 0:
    await transp.sendErrorResponse(frame, CallsTokenOpcode, invalidTokenError())
    return

  # maxcalls documents opcode 158 as CallTokenRequest.  A full Calls API
  # implementation will validate this token later; for now it encodes enough
  # local identity for localhost federation experiments.
  let callToken = "openmax-call:" & $ctx.currentUserId & ":" & generateRandomString(64)
  ctx.app.calls.registerCallToken(callToken, ctx.currentUserId)
  await transp.sendResponseObject(
    frame,
    CmdOk,
    CallsTokenOpcode,
    OnemeCallTokenResponse(token: callToken)
  )

proc handleContactInfo(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  if not await requireLoggedIn(ctx, transp, frame, ContactInfoOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeContactInfoPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactInfoOpcode, invalidPayloadError())
      return

  ## CONTACT_INFO (32): lookup users by id, enriched with the requester's
  ## custom names / block status. Ported from search.py::contact_info.
  let avatarBase = ctx.app.config.service_urls.avatar_base_url
  var contacts = newJArray()
  for userId in payload.contactIds:
    let user = ctx.app.db.findUserById(userId)
    if user.len != 0:
      let crow = ctx.app.db.findContact(ctx.currentUserId, userId)
      let blocked = crow.len != 0 and rowString(crow, "is_blocked") in ["1", "TRUE", "true"]
      contacts.add generateOnemeProfileJson(
        user, avatarBase, includeProfileOptions = false,
        customFirstName = (if crow.len != 0: rowString(crow, "custom_firstname") else: ""),
        customLastName = (if crow.len != 0: rowString(crow, "custom_lastname") else: ""),
        blocked = blocked)

  await transp.sendResponseBytes(frame, CmdOk, ContactInfoOpcode,
    packJsonPayload(%*{"contacts": contacts}))

proc handleContactUpdate(ctx: ConnectionContext,
                         transp: MobileTransport,
                         frame: MobileFrame): Future[void] {.async.} =
  ## CONTACT_UPDATE (34): ADD / REMOVE / BLOCK / UNBLOCK / UPDATE.
  ## Ported from contacts.py::contact_update.
  if not await requireLoggedIn(ctx, transp, frame, ContactUpdateOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeFullContactUpdatePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, invalidPayloadError())
      return

  let avatarBase = ctx.app.config.service_urls.avatar_base_url
  let contactId = payload.contactId

  proc contactProfileJson(user: DbRow): JsonNode =
    generateOnemeProfileJson(
      user, avatarBase, includeProfileOptions = false,
      customFirstName = payload.firstName, customLastName = payload.lastName)

  case payload.action.toUpperAscii()
  of "ADD":
    let user = ctx.app.db.findUserById(contactId)
    if user.len == 0:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, userNotFoundError())
      return
    if ctx.app.db.findContact(ctx.currentUserId, contactId).len != 0:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, invalidPayloadError())
      return
    ctx.app.db.addContactFull(ctx.currentUserId, contactId, payload.firstName, payload.lastName, false)
    let chatId = ctx.currentUserId xor contactId
    ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId, contactId])
    await transp.sendResponseBytes(frame, CmdOk, ContactUpdateOpcode,
      packJsonPayload(%*{"contact": contactProfileJson(user)}))
  of "REMOVE":
    ctx.app.db.removeContact(ctx.currentUserId, contactId)
    await transp.sendNilResponse(frame, CmdOk, ContactUpdateOpcode)
  of "BLOCK":
    if ctx.app.db.findContact(ctx.currentUserId, contactId).len != 0:
      ctx.app.db.setContactBlocked(ctx.currentUserId, contactId, true)
    else:
      let user = ctx.app.db.findUserById(contactId)
      if user.len == 0:
        await transp.sendErrorResponse(frame, ContactUpdateOpcode, userNotFoundError())
        return
      ctx.app.db.addContactFull(ctx.currentUserId, contactId, payload.firstName, payload.lastName, true)
    await transp.sendNilResponse(frame, CmdOk, ContactUpdateOpcode)
  of "UNBLOCK":
    if ctx.app.db.findContact(ctx.currentUserId, contactId).len == 0:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, userNotFoundError())
      return
    ctx.app.db.setContactBlocked(ctx.currentUserId, contactId, false)
    await transp.sendNilResponse(frame, CmdOk, ContactUpdateOpcode)
  of "UPDATE":
    if ctx.app.db.findContact(ctx.currentUserId, contactId).len == 0:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, userNotFoundError())
      return
    ctx.app.db.updateContactNames(ctx.currentUserId, contactId, payload.firstName, payload.lastName)
    let user = ctx.app.db.findUserById(contactId)
    if user.len == 0:
      await transp.sendErrorResponse(frame, ContactUpdateOpcode, userNotFoundError())
      return
    await transp.sendResponseBytes(frame, CmdOk, ContactUpdateOpcode,
      packJsonPayload(%*{"contact": contactProfileJson(user)}))
  else:
    await transp.sendErrorResponse(frame, ContactUpdateOpcode, invalidPayloadError())

proc handleContactList(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  ## CONTACT_LIST (36). Ported from contacts.py::contact_list — the reference
  ## server only returns a populated list for status == "BLOCKED"; all other
  ## statuses respond with an empty contacts array.
  if not await requireLoggedIn(ctx, transp, frame, ContactListOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeContactListPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactListOpcode, invalidPayloadError())
      return

  let avatarBase = ctx.app.config.service_urls.avatar_base_url
  var contacts = newJArray()
  if payload.status.toUpperAscii() == "BLOCKED":
    for row in ctx.app.db.blockedContactsForUser(ctx.currentUserId, payload.count):
      let contactId = rowInt64(row, "contact_id")
      let user = ctx.app.db.findUserById(contactId)
      if user.len != 0:
        contacts.add generateOnemeProfileJson(
          user, avatarBase, includeProfileOptions = false,
          customFirstName = rowString(row, "custom_firstname"),
          customLastName = rowString(row, "custom_lastname"),
          blocked = true)

  await transp.sendResponseBytes(frame, CmdOk, ContactListOpcode,
    packJsonPayload(%*{"contacts": contacts}))

proc handleContactInfoByPhone(ctx: ConnectionContext,
                              transp: MobileTransport,
                              frame: MobileFrame): Future[void] {.async.} =
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeContactByPhonePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactInfoByPhoneOpcode, invalidPayloadError())
      return

  let phone = normalizePhoneNumber(payload.phone)
  if phone.len == 0:
    await transp.sendErrorResponse(frame, ContactInfoByPhoneOpcode, invalidPayloadError())
    return

  let user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    await transp.sendErrorResponse(frame, ContactInfoByPhoneOpcode, userNotFoundError())
    return

  if ctx.currentUserId != 0:
    let contactId = rowInt64(user, "id")
    let chatId = if contactId == ctx.currentUserId: ctx.currentUserId else: ctx.currentUserId xor contactId
    if contactId == ctx.currentUserId:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId])
    else:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId, contactId])

  let crow =
    if ctx.currentUserId != 0: ctx.app.db.findContact(ctx.currentUserId, rowInt64(user, "id"))
    else: initTable[string, string]()
  let blocked = crow.len != 0 and rowString(crow, "is_blocked") in ["1", "TRUE", "true"]
  let contact = generateOnemeProfileJson(
    user, ctx.app.config.service_urls.avatar_base_url, includeProfileOptions = false,
    customFirstName = (if crow.len != 0: rowString(crow, "custom_firstname") else: ""),
    customLastName = (if crow.len != 0: rowString(crow, "custom_lastname") else: ""),
    blocked = blocked)

  await transp.sendResponseBytes(frame, CmdOk, ContactInfoByPhoneOpcode,
    packJsonPayload(%*{"contact": contact}))

proc handleProfile(ctx: ConnectionContext,
                   transp: MobileTransport,
                   frame: MobileFrame): Future[void] {.async.} =
  ## PROFILE (16): return the logged-in user's own profile. Ported from
  ## Python oneme/processors/main.py::profile (update path is a no-op stub here,
  ## matching the reference server which only persists via separate flows).
  if not await requireLoggedIn(ctx, transp, frame, ProfileOpcode):
    return

  let user = ctx.app.db.findUserById(ctx.currentUserId)
  if user.len == 0:
    await transp.sendErrorResponse(frame, ProfileOpcode, userNotFoundError())
    return

  let profile = generateOnemeProfileJson(
    user,
    ctx.app.config.service_urls.avatar_base_url,
    includeProfileOptions = true
  )
  await transp.sendResponseBytes(frame, CmdOk, ProfileOpcode, packJsonPayload(%*{"profile": profile}))

proc handleAssetsUpdate(ctx: ConnectionContext,
                        transp: MobileTransport,
                        frame: MobileFrame): Future[void] {.async.} =
  ## ASSETS_UPDATE (27): sticker store sync. Ported from assets.py — the
  ## reference server returns an empty-but-structured sticker catalogue.
  if not await requireLoggedIn(ctx, transp, frame, AssetsUpdateOpcode):
    return
  let response = %*{
    "sync": nowUnixMs(),
    "stickerSetsUpdates": newJObject(),
    "stickersUpdates": newJObject(),
    "stickersOrder": [
      "RECENT", "FAVORITE_STICKERS", "FAVORITE_STICKER_SETS",
      "TOP", "NEW", "NEW_STICKER_SETS"
    ],
    "sections": [
      {"id": "RECENT", "type": "RECENTS", "recentsList": []},
      {"id": "FAVORITE_STICKERS", "type": "STICKERS", "stickers": [], "marker": newJNull()},
      {"id": "FAVORITE_STICKER_SETS", "type": "STICKER_SETS", "stickerSets": [], "marker": newJNull()},
      {"id": "TOP", "type": "STICKERS", "stickers": [], "marker": newJNull()},
      {"id": "NEW", "type": "STICKERS", "stickers": [], "marker": newJNull()},
      {"id": "NEW_STICKER_SETS", "type": "STICKER_SETS", "stickerSets": [], "marker": newJNull()}
    ]
  }
  await transp.sendResponseBytes(frame, CmdOk, AssetsUpdateOpcode, packJsonPayload(response))

proc handleAssetsGet(ctx: ConnectionContext,
                     transp: MobileTransport,
                     frame: MobileFrame): Future[void] {.async.} =
  ## ASSETS_GET (26). Ported from assets.py.
  if not await requireLoggedIn(ctx, transp, frame, AssetsGetOpcode):
    return
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeAssetsGetPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AssetsGetOpcode, invalidPayloadError())
      return
  let response =
    if payload.`type` == "STICKER_SET":
      %*{"stickerSets": [], "marker": newJNull()}
    else:
      %*{"stickers": [], "marker": newJNull()}
  await transp.sendResponseBytes(frame, CmdOk, AssetsGetOpcode, packJsonPayload(response))

proc handleAssetsGetByIds(ctx: ConnectionContext,
                          transp: MobileTransport,
                          frame: MobileFrame): Future[void] {.async.} =
  ## ASSETS_GET_BY_IDS (28). Ported from assets.py.
  if not await requireLoggedIn(ctx, transp, frame, AssetsGetByIdsOpcode):
    return
  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeAssetsGetByIdsPayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, AssetsGetByIdsOpcode, invalidPayloadError())
      return
  let response =
    if payload.`type` == "STICKER_SET":
      %*{"stickerSets": []}
    else:
      %*{"stickers": []}
  await transp.sendResponseBytes(frame, CmdOk, AssetsGetByIdsOpcode, packJsonPayload(response))

proc handleAssetsAck(ctx: ConnectionContext,
                     transp: MobileTransport,
                     frame: MobileFrame,
                     opcode: uint16): Future[void] {.async.} =
  ## ASSETS_ADD / REMOVE / MOVE / LIST_MODIFY: acknowledge with empty payload.
  ## Ported from assets.py — these mutate client-side favourites which this
  ## server does not persist yet, so the reference returns `{}`.
  if not await requireLoggedIn(ctx, transp, frame, opcode):
    return
  await transp.sendResponseBytes(frame, CmdOk, opcode, packJsonPayload(newJObject()))

proc handleFoldersUpdate(ctx: ConnectionContext,
                         transp: MobileTransport,
                         frame: MobileFrame): Future[void] {.async.} =
  ## FOLDERS_UPDATE (274): create/update a chat folder. Ported from folders.py.
  if not await requireLoggedIn(ctx, transp, frame, FoldersUpdateOpcode):
    return

  let payload =
    try:
      unpackJsonPayload(frame.payload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, FoldersUpdateOpcode, invalidPayloadError())
      return

  let id = payload{"id"}.getStr("")
  let title = payload{"title"}.getStr("")
  if id.len == 0 or title.len == 0:
    await transp.sendErrorResponse(frame, FoldersUpdateOpcode, invalidPayloadError())
    return

  let filters = payload.jsonArrayOrEmpty("filters")
  let includeArr = payload.jsonArrayOrEmpty("include")
  let updateTime = nowUnixMs()
  let phone = normalizePhone(ctx.currentPhone)
  let sortOrder = ctx.app.db.nextFolderSortOrder(phone)

  ctx.app.db.upsertFolder(id, phone, title, $filters, $includeArr, updateTime, sortOrder)

  let order = ctx.app.db.folderOrder(phone)
  var orderJson = newJArray()
  for fid in order: orderJson.add %fid

  let response = %*{
    "folder": {
      "id": id,
      "title": title,
      "include": includeArr,
      "filters": filters,
      "updateTime": updateTime,
      "options": [],
      "sourceId": 1
    },
    "folderSync": updateTime,
    "foldersOrder": orderJson
  }
  await transp.sendResponseBytes(frame, CmdOk, FoldersUpdateOpcode, packJsonPayload(response))

  # The reference server also pushes a config-hash notification afterwards.
  await transp.sendResponseBytes(frame, 0'u8, NotifConfigOpcode,
    packJsonPayload(%*{"config": {"hash": "0"}}))

proc handleContactAddByPhone(ctx: ConnectionContext,
                             transp: MobileTransport,
                             frame: MobileFrame): Future[void] {.async.} =
  ## CONTACT_ADD_BY_PHONE (41). Ported from contacts.py.
  if not await requireLoggedIn(ctx, transp, frame, ContactCreateOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeContactAddByPhonePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactCreateOpcode, invalidPayloadError())
      return

  let phone = normalizePhoneNumber(payload.phone)
  if phone.len == 0 or payload.firstName.len == 0:
    await transp.sendErrorResponse(frame, ContactCreateOpcode, invalidPayloadError())
    return

  let user = ctx.app.db.findUserByPhone(phone)
  if user.len == 0:
    await transp.sendErrorResponse(frame, ContactCreateOpcode, userNotFoundError())
    return

  let contactId = rowInt64(user, "id")
  let isNew = ctx.app.db.findContact(ctx.currentUserId, contactId).len == 0
  if isNew:
    ctx.app.db.addContactFull(ctx.currentUserId, contactId, payload.firstName, payload.lastName, false)
    let chatId = if contactId == ctx.currentUserId: ctx.currentUserId else: ctx.currentUserId xor contactId
    if contactId == ctx.currentUserId:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId])
    else:
      ctx.app.db.ensureChat(chatId, ctx.currentUserId, "DIALOG", [ctx.currentUserId, contactId])

  let contact = generateOnemeProfileJson(
    user, ctx.app.config.service_urls.avatar_base_url,
    includeProfileOptions = false,
    customFirstName = payload.firstName,
    customLastName = payload.lastName
  )
  await transp.sendResponseBytes(frame, CmdOk, ContactCreateOpcode,
    packJsonPayload(%*{"new": isNew, "contact": contact}))

proc presenceForUser(ctx: ConnectionContext, userId: int64, nowS: int64): JsonNode =
  ## Mirror Python tools.collect_presence using connected transports as the
  ## online signal (Nim has no separate clients status map).
  if ctx.app.transportsForUser(userId).len > 0:
    %*{"seen": nowS, "status": 2}
  else:
    let last = ctx.app.db.lastSeenForUser(userId)
    %*{"seen": last}

proc handleContactPresence(ctx: ConnectionContext,
                           transp: MobileTransport,
                           frame: MobileFrame): Future[void] {.async.} =
  ## CONTACT_PRESENCE (35). Ported from contacts.py::contact_presence.
  if not await requireLoggedIn(ctx, transp, frame, ContactPresenceOpcode):
    return

  let payload =
    try:
      unpackMapPayload(frame.payload, OnemeContactPresencePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ContactPresenceOpcode, invalidPayloadError())
      return

  let nowS = store.nowUnix()
  var presence = newJObject()
  for contactId in payload.contactIds:
    presence[$contactId] = presenceForUser(ctx, contactId, nowS)

  await transp.sendResponseBytes(frame, CmdOk, ContactPresenceOpcode,
    packJsonPayload(%*{"presence": presence, "time": nowUnixMs()}))

proc handleChatSubscribe(ctx: ConnectionContext,
                         transp: MobileTransport,
                         frame: MobileFrame): Future[void] {.async.} =
  ## CHAT_SUBSCRIBE (75). Ported from chats.py — validate then ack with nil.
  if not await requireLoggedIn(ctx, transp, frame, ChatSubscribeOpcode):
    return
  if frame.payload.len > 0:
    try:
      discard unpackMapPayload(frame.payload, OnemeChatSubscribePayload)
    except MsgPackCodecError:
      await transp.sendErrorResponse(frame, ChatSubscribeOpcode, invalidPayloadError())
      return
  await transp.sendNilResponse(frame, CmdOk, ChatSubscribeOpcode)

proc handleComplainReasonsGet(ctx: ConnectionContext,
                              transp: MobileTransport,
                              frame: MobileFrame): Future[void] {.async.} =
  ## COMPLAIN_REASONS_GET (162). Ported from complaints.py.
  if not await requireLoggedIn(ctx, transp, frame, ComplainReasonsGetOpcode):
    return
  let response = %*{
    "complains": parseJson(ComplainReasonsJson),
    "complainSync": store.nowUnix()
  }
  await transp.sendResponseBytes(frame, CmdOk, ComplainReasonsGetOpcode, packJsonPayload(response))

proc handleVideoChatHistory(ctx: ConnectionContext,
                            transp: MobileTransport,
                            frame: MobileFrame): Future[void] {.async.} =
  ## VIDEO_CHAT_HISTORY (79). Ported from calls.py — empty history stub.
  if not await requireLoggedIn(ctx, transp, frame, VideoChatHistoryOpcode):
    return
  let response = %*{
    "hasMore": false,
    "history": [],
    "backwardMarker": 0,
    "forwardMarker": 0
  }
  await transp.sendResponseBytes(frame, CmdOk, VideoChatHistoryOpcode, packJsonPayload(response))

proc handleTcpFrame*(ctx: ConnectionContext,
                     transp: MobileTransport,
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
  of LogoutOpcode:
    await handleLogout(ctx, transp, frame)
  of SessionsInfoOpcode:
    await handleSessionsInfo(ctx, transp, frame)
  of ConfigOpcode:
    await handleConfig(ctx, transp, frame)
  of ProfileOpcode:
    await handleProfile(ctx, transp, frame)
  of FoldersGetOpcode:
    await handleFoldersGet(ctx, transp, frame)
  of FoldersUpdateOpcode:
    await handleFoldersUpdate(ctx, transp, frame)
  of AssetsUpdateOpcode:
    await handleAssetsUpdate(ctx, transp, frame)
  of AssetsGetOpcode:
    await handleAssetsGet(ctx, transp, frame)
  of AssetsGetByIdsOpcode:
    await handleAssetsGetByIds(ctx, transp, frame)
  of AssetsAddOpcode:
    await handleAssetsAck(ctx, transp, frame, AssetsAddOpcode)
  of AssetsRemoveOpcode:
    await handleAssetsAck(ctx, transp, frame, AssetsRemoveOpcode)
  of AssetsMoveOpcode:
    await handleAssetsAck(ctx, transp, frame, AssetsMoveOpcode)
  of AssetsListModifyOpcode:
    await handleAssetsAck(ctx, transp, frame, AssetsListModifyOpcode)
  of ContactCreateOpcode:
    await handleContactAddByPhone(ctx, transp, frame)
  of ContactPresenceOpcode:
    await handleContactPresence(ctx, transp, frame)
  of ChatSubscribeOpcode:
    await handleChatSubscribe(ctx, transp, frame)
  of ComplainReasonsGetOpcode:
    await handleComplainReasonsGet(ctx, transp, frame)
  of VideoChatHistoryOpcode:
    await handleVideoChatHistory(ctx, transp, frame)
  of ChatsListOpcode:
    await handleChatsList(ctx, transp, frame)
  of ChatInfoOpcode:
    await handleChatInfo(ctx, transp, frame)
  of SyncOpcode:
    await handleSync(ctx, transp, frame)
  of MsgSendOpcode:
    await handleSendMessage(ctx, transp, frame)
  of MsgEditOpcode:
    await handleEditMessage(ctx, transp, frame)
  of MsgDeleteOpcode:
    await handleDeleteMessages(ctx, transp, frame)
  of ChatMarkOpcode:
    await handleChatMark(ctx, transp, frame)
  of MsgTypingOpcode:
    await handleTyping(ctx, transp, frame)
  of ChatHistoryOpcode:
    await handleChatHistory(ctx, transp, frame)
  of MsgGetOpcode:
    await handleGetMessages(ctx, transp, frame)
  of PhotoUploadOpcode:
    await handleUploadRequest(ctx, transp, frame, PhotoUploadOpcode, "photo")
  of VideoUploadOpcode:
    await handleUploadRequest(ctx, transp, frame, VideoUploadOpcode, "video")
  of FileUploadOpcode:
    await handleUploadRequest(ctx, transp, frame, FileUploadOpcode, "file")
  of ContactInfoOpcode:
    await handleContactInfo(ctx, transp, frame)
  of ContactUpdateOpcode:
    await handleContactUpdate(ctx, transp, frame)
  of ContactListOpcode:
    await handleContactList(ctx, transp, frame)
  of ContactInfoByPhoneOpcode:
    await handleContactInfoByPhone(ctx, transp, frame)
  of CallsTokenOpcode:
    await handleCallsToken(ctx, transp, frame)
  else:
    await transp.sendErrorResponse(frame, frame.header.opcode, notImplementedError())
