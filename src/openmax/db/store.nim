import std/[os, strutils, times, random, json, tables]
import ../config/types
import ../crypto/sha256
import ./sqlite_abi

type
  AppDatabase* = ref object
    kind*: string
    sqlite*: SqliteDb

const
  DefaultUserSettingsJson* = $(%*{
    "CHATS_PUSH_NOTIFICATION": "ON",
    "PUSH_DETAILS": true,
    "PUSH_SOUND": "DEFAULT",
    "INACTIVE_TTL": "6M",
    "CHATS_QUICK_REPLY": false,
    "SHOW_READ_MARK": true,
    "AUDIO_TRANSCRIPTION_ENABLED": true,
    "CHATS_LED": 65535,
    "SEARCH_BY_PHONE": "ALL",
    "INCOMING_CALL": "ALL",
    "DOUBLE_TAP_REACTION_DISABLED": false,
    "SAFE_MODE_NO_PIN": false,
    "CHATS_PUSH_SOUND": "DEFAULT",
    "DOUBLE_TAP_REACTION_VALUE": newJNull(),
    "FAMILY_PROTECTION": "OFF",
    "LED": 65535,
    "HIDDEN": false,
    "VIBR": true,
    "CHATS_INVITE": "ALL",
    "PUSH_NEW_CONTACTS": false,
    "UNSAFE_FILES": true,
    "DONT_DISTURB_UNTIL": 0,
    "CHATS_VIBR": true,
    "CONTENT_LEVEL_ACCESS": false,
    "STICKERS_SUGGEST": "ON",
    "SAFE_MODE": false,
    "M_CALL_PUSH_NOTIFICATION": "ON",
    "QUICK_REPLY": false
  })

proc nowUnix*(): int64 =
  epochTime().int64

proc nowUnixMs*(): int64 =
  (epochTime() * 1000.0).int64

proc normalizePhone*(phone: string): string =
  for ch in phone:
    if ch in {'0'..'9'}:
      result.add ch

proc openDatabase*(config: DatabaseConfig, projectDir: string): AppDatabase =
  if config.kind.toLowerAscii() != "sqlite":
    raise newException(SqliteError, "Only sqlite database is supported at this stage")

  let dbPath = projectDir / config.sqlite_file
  createDir(parentDir(dbPath))

  let sqlite = openSqlite(dbPath)
  let schemaPath = projectDir / "sql" / "tables.mysql.sql"
  let schema = readFile(schemaPath)
  sqlite.execScript(schema)

  randomize(int(nowUnix()))
  AppDatabase(kind: config.kind, sqlite: sqlite)

proc close*(db: AppDatabase) =
  if db.isNil:
    return
  if not db.sqlite.isNil:
    db.sqlite.close()

proc rowLen*(row: DbRow): int =
  row.len

proc dbRowString(row: DbRow, key: string): string =
  row.getOrDefault(key, "")

proc findUserByPhone*(db: AppDatabase, phone: string): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM users WHERE phone = ? LIMIT 1",
    [textValue(phone)]
  )

proc findUserById*(db: AppDatabase, id: int64): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM users WHERE id = ? LIMIT 1",
    [intValue(id)]
  )

proc findUserDataByPhone*(db: AppDatabase, phone: string): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM user_data WHERE phone = ? LIMIT 1",
    [textValue(phone)]
  )

proc insertAuthToken*(db: AppDatabase,
                      phone, token, code: string,
                      expires: int64,
                      state: string) =
  db.sqlite.exec(
    "INSERT INTO auth_tokens (phone, token_hash, code_hash, expires, state) VALUES (?, ?, ?, ?, ?)",
    [
      textValue(phone),
      textValue(sha256Hex(token)),
      textValue(sha256Hex(code)),
      textValue($expires),
      if state.len > 0: textValue(state) else: nullValue()
    ]
  )

proc findAuthToken*(db: AppDatabase, token: string): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM auth_tokens WHERE token_hash = ? AND CAST(expires AS INTEGER) > ? LIMIT 1",
    [textValue(sha256Hex(token)), intValue(nowUnix())]
  )

proc updateAuthTokenState*(db: AppDatabase, token, state: string) =
  db.sqlite.exec(
    "UPDATE auth_tokens SET state = ? WHERE token_hash = ?",
    [textValue(state), textValue(sha256Hex(token))]
  )

proc deleteAuthToken*(db: AppDatabase, token: string) =
  db.sqlite.exec(
    "DELETE FROM auth_tokens WHERE token_hash = ?",
    [textValue(sha256Hex(token))]
  )

proc insertSessionToken*(db: AppDatabase,
                         phone, token, deviceType, deviceName, location: string,
                         issuedAtMs: int64) =
  db.sqlite.exec(
    "INSERT INTO tokens (phone, token_hash, device_type, device_name, location, time) VALUES (?, ?, ?, ?, ?, ?)",
    [
      textValue(phone),
      textValue(sha256Hex(token)),
      textValue(deviceType),
      textValue(deviceName),
      textValue(location),
      textValue($issuedAtMs)
    ]
  )

proc findSessionToken*(db: AppDatabase, token: string): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM tokens WHERE token_hash = ? LIMIT 1",
    [textValue(sha256Hex(token))]
  )

proc generateUserId*(db: AppDatabase): int64 =
  while true:
    let candidate = rand(2_147_383_647 - 100_000) + 100_000
    let row = db.findUserById(candidate.int64)
    if row.len == 0:
      return candidate.int64

proc insertUserData*(db: AppDatabase, phone: string) =
  db.sqlite.exec(
    "INSERT INTO user_data (phone, user_config, chat_config) VALUES (?, ?, ?)",
    [textValue(phone), textValue(DefaultUserSettingsJson), textValue("{}")]
  )

proc insertDefaultFolder*(db: AppDatabase, phone: string) =
  db.sqlite.exec(
    "INSERT INTO user_folders (id, phone, title, sort_order) VALUES ('all.chat.folder', ?, 'Все', 0)",
    [textValue(phone)]
  )

proc createOnemeUser*(db: AppDatabase,
                      phone, firstName, lastName: string): DbRow =
  let userId = db.generateUserId()
  let nowMs = nowUnixMs()
  let nowS = nowUnix()

  db.sqlite.exec(
    """
    INSERT INTO users
      (id, phone, telegram_id, firstname, lastname, username,
       profileoptions, options, accountstatus, updatetime, lastseen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    [
      intValue(userId),
      textValue(phone),
      nullValue(),
      textValue(firstName),
      if lastName.len > 0: textValue(lastName) else: nullValue(),
      nullValue(),
      textValue("[]"),
      textValue("[\"TT\", \"ONEME\"]"),
      textValue("0"),
      textValue($nowMs),
      textValue($nowS)
    ]
  )
  db.insertUserData(phone)
  db.insertDefaultFolder(phone)
  db.findUserById(userId)

proc nextMessageId*(db: AppDatabase): int64 =
  let row = db.sqlite.queryRow("SELECT COALESCE(MAX(id), 0) AS id FROM messages")
  dbRowString(row, "id").parseBiggestInt().int64 + 1

proc findChatById*(db: AppDatabase, chatId: int64): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM chats WHERE id = ? LIMIT 1",
    [intValue(chatId)]
  )

proc participantsOfChat*(db: AppDatabase, chatId: int64): seq[int64] =
  for row in db.sqlite.queryAll(
    "SELECT user_id FROM chat_participants WHERE chat_id = ? ORDER BY user_id",
    [intValue(chatId)]
  ):
    result.add dbRowString(row, "user_id").parseBiggestInt().int64

proc ensureChat*(db: AppDatabase,
                 chatId, owner: int64,
                 kind: string,
                 participants: openArray[int64]) =
  if db.findChatById(chatId).len == 0:
    db.sqlite.exec(
      "INSERT INTO chats (id, owner, type) VALUES (?, ?, ?)",
      [intValue(chatId), intValue(owner), textValue(kind)]
    )

  for userId in participants:
    db.sqlite.exec(
      "INSERT OR IGNORE INTO chat_participants (chat_id, user_id) VALUES (?, ?)",
      [intValue(chatId), intValue(userId)]
    )

proc chatsForUser*(db: AppDatabase, userId: int64): seq[DbRow] =
  db.sqlite.queryAll(
    """
    SELECT c.* FROM chats c
      JOIN chat_participants cp ON cp.chat_id = c.id
    WHERE cp.user_id = ?
    ORDER BY c.id DESC
    """,
    [intValue(userId)]
  )

proc lastMessageForChat*(db: AppDatabase, chatId: int64): DbRow =
  db.sqlite.queryRow(
    "SELECT * FROM messages WHERE chat_id = ? ORDER BY CAST(time AS INTEGER) DESC, id DESC LIMIT 1",
    [intValue(chatId)]
  )

proc messagesForChat*(db: AppDatabase, chatId: int64, limit: int): seq[DbRow] =
  db.sqlite.queryAll(
    "SELECT * FROM messages WHERE chat_id = ? ORDER BY CAST(time AS INTEGER) DESC, id DESC LIMIT ?",
    [intValue(chatId), intValue(limit.int64)]
  )

proc messagesByIds*(db: AppDatabase, chatId: int64, ids: openArray[int64]): seq[DbRow] =
  for id in ids:
    let row = db.sqlite.queryRow(
      "SELECT * FROM messages WHERE chat_id = ? AND id = ? LIMIT 1",
      [intValue(chatId), intValue(id)]
    )
    if row.len != 0:
      result.add row

proc insertMessage*(db: AppDatabase,
                    chatId, sender, cid: int64,
                    text, attachesJson, elementsJson, kind: string,
                    createdAtMs: int64): DbRow =
  let id = db.nextMessageId()
  db.sqlite.exec(
    """
    INSERT INTO messages (id, chat_id, sender, time, text, attaches, cid, elements, type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    [
      intValue(id),
      intValue(chatId),
      intValue(sender),
      textValue($createdAtMs),
      textValue(text),
      textValue(attachesJson),
      textValue($cid),
      textValue(elementsJson),
      textValue(kind)
    ]
  )
  db.sqlite.queryRow("SELECT * FROM messages WHERE id = ? LIMIT 1", [intValue(id)])

proc createTamtamUser*(db: AppDatabase,
                       phone, name: string): DbRow =
  let userId = db.generateUserId()
  let nowMs = nowUnixMs()
  let nowS = nowUnix()

  db.sqlite.exec(
    """
    INSERT INTO users
      (id, phone, telegram_id, firstname, lastname, username,
       profileoptions, options, accountstatus, updatetime, lastseen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    [
      intValue(userId),
      textValue(phone),
      nullValue(),
      textValue(name),
      nullValue(),
      nullValue(),
      textValue("[]"),
      textValue("[\"TT\", \"ONEME\"]"),
      textValue("0"),
      textValue($nowMs),
      textValue($nowS)
    ]
  )
  db.insertUserData(phone)
  db.insertDefaultFolder(phone)
  db.findUserById(userId)
