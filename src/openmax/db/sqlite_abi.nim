import std/[strformat, tables]

type
  SqliteError* = object of CatchableError

  SqliteNative = object
  SqliteStmtNative = object

  SqliteDb* = ref object
    handle*: ptr SqliteNative

  DbValueKind* = enum
    dvNull
    dvInt
    dvText

  DbValue* = object
    case kind*: DbValueKind
    of dvNull:
      discard
    of dvInt:
      intValue*: int64
    of dvText:
      textValue*: string

  DbRow* = Table[string, string]

const SqliteDynLib =
  when defined(windows): "sqlite3.dll"
  elif defined(macosx): "libsqlite3.0.dylib"
  else: "libsqlite3.so.0"

  SQLITE_OK = 0.cint
  SQLITE_ROW = 100.cint
  SQLITE_DONE = 101.cint
  SQLITE_TRANSIENT = cast[pointer](-1)

proc sqlite3_open(filename: cstring, ppDb: ptr ptr SqliteNative): cint {.importc: "sqlite3_open", dynlib: SqliteDynLib.}
proc sqlite3_close(db: ptr SqliteNative): cint {.importc: "sqlite3_close", dynlib: SqliteDynLib.}
proc sqlite3_errmsg(db: ptr SqliteNative): cstring {.importc: "sqlite3_errmsg", dynlib: SqliteDynLib.}
proc sqlite3_exec(db: ptr SqliteNative, sql: cstring,
                  callback: pointer, arg: pointer,
                  errmsg: ptr cstring): cint {.importc: "sqlite3_exec", dynlib: SqliteDynLib.}
proc sqlite3_free(p: pointer) {.importc: "sqlite3_free", dynlib: SqliteDynLib.}
proc sqlite3_prepare_v2(db: ptr SqliteNative, sql: cstring, nByte: cint,
                        ppStmt: ptr ptr SqliteStmtNative,
                        pzTail: ptr cstring): cint {.importc: "sqlite3_prepare_v2", dynlib: SqliteDynLib.}
proc sqlite3_finalize(stmt: ptr SqliteStmtNative): cint {.importc: "sqlite3_finalize", dynlib: SqliteDynLib.}
proc sqlite3_bind_text(stmt: ptr SqliteStmtNative, idx: cint,
                       value: cstring, n: cint,
                       destructor: pointer): cint {.importc: "sqlite3_bind_text", dynlib: SqliteDynLib.}
proc sqlite3_bind_int64(stmt: ptr SqliteStmtNative, idx: cint, value: int64): cint {.importc: "sqlite3_bind_int64", dynlib: SqliteDynLib.}
proc sqlite3_bind_null(stmt: ptr SqliteStmtNative, idx: cint): cint {.importc: "sqlite3_bind_null", dynlib: SqliteDynLib.}
proc sqlite3_step(stmt: ptr SqliteStmtNative): cint {.importc: "sqlite3_step", dynlib: SqliteDynLib.}
proc sqlite3_column_count(stmt: ptr SqliteStmtNative): cint {.importc: "sqlite3_column_count", dynlib: SqliteDynLib.}
proc sqlite3_column_name(stmt: ptr SqliteStmtNative, idx: cint): cstring {.importc: "sqlite3_column_name", dynlib: SqliteDynLib.}
proc sqlite3_column_text(stmt: ptr SqliteStmtNative, idx: cint): cstring {.importc: "sqlite3_column_text", dynlib: SqliteDynLib.}

proc nullValue*(): DbValue =
  DbValue(kind: dvNull)

proc intValue*(value: int64): DbValue =
  DbValue(kind: dvInt, intValue: value)

proc textValue*(value: string): DbValue =
  DbValue(kind: dvText, textValue: value)

proc isEmpty*(row: DbRow): bool =
  row.len == 0

proc errorMessage(db: ptr SqliteNative): string =
  if db.isNil:
    "sqlite error"
  else:
    $sqlite3_errmsg(db)

proc raiseSqlite(db: ptr SqliteNative, what: string, extra = "") {.noreturn.} =
  let suffix = if extra.len > 0: ": " & extra else: ""
  raise newException(SqliteError, &"{what}: {errorMessage(db)}{suffix}")

proc openSqlite*(path: string): SqliteDb =
  var handle: ptr SqliteNative
  let rc = sqlite3_open(path.cstring, addr handle)
  if rc != SQLITE_OK:
    raiseSqlite(handle, "sqlite3_open", path)
  SqliteDb(handle: handle)

proc close*(db: SqliteDb) =
  if db.isNil or db.handle.isNil:
    return
  discard sqlite3_close(db.handle)
  db.handle = nil

proc execScript*(db: SqliteDb, script: string) =
  var errmsg: cstring
  let rc = sqlite3_exec(db.handle, script.cstring, nil, nil, addr errmsg)
  if rc != SQLITE_OK:
    let extra = if errmsg.isNil: "" else: $errmsg
    if not errmsg.isNil:
      sqlite3_free(cast[pointer](errmsg))
    raiseSqlite(db.handle, "sqlite3_exec", extra)

proc bindParam(stmt: ptr SqliteStmtNative, idx: int, value: DbValue, db: ptr SqliteNative) =
  let rc =
    case value.kind
    of dvNull:
      sqlite3_bind_null(stmt, cint(idx))
    of dvInt:
      sqlite3_bind_int64(stmt, cint(idx), value.intValue)
    of dvText:
      sqlite3_bind_text(stmt, cint(idx), value.textValue.cstring, cint(value.textValue.len), SQLITE_TRANSIENT)

  if rc != SQLITE_OK:
    raiseSqlite(db, &"sqlite3_bind({idx})")

proc prepare(db: SqliteDb, query: string): ptr SqliteStmtNative =
  var stmt: ptr SqliteStmtNative
  let rc = sqlite3_prepare_v2(db.handle, query.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    raiseSqlite(db.handle, "sqlite3_prepare_v2", query)
  stmt

proc exec*(db: SqliteDb, query: string, params: openArray[DbValue] = []) =
  let stmt = prepare(db, query)
  try:
    for i, value in params:
      bindParam(stmt, i + 1, value, db.handle)

    let rc = sqlite3_step(stmt)
    if rc != SQLITE_DONE:
      raiseSqlite(db.handle, "sqlite3_step/exec", query)
  finally:
    discard sqlite3_finalize(stmt)

proc queryAll*(db: SqliteDb, query: string,
               params: openArray[DbValue] = []): seq[DbRow] =
  let stmt = prepare(db, query)
  try:
    for i, value in params:
      bindParam(stmt, i + 1, value, db.handle)

    while true:
      let rc = sqlite3_step(stmt)
      case rc
      of SQLITE_ROW:
        var row = initTable[string, string]()
        let count = int(sqlite3_column_count(stmt))
        for i in 0 ..< count:
          let name = $sqlite3_column_name(stmt, cint(i))
          let value = sqlite3_column_text(stmt, cint(i))
          row[name] = if value.isNil: "" else: $value
        result.add row
      of SQLITE_DONE:
        break
      else:
        raiseSqlite(db.handle, "sqlite3_step/queryAll", query)
  finally:
    discard sqlite3_finalize(stmt)

proc queryRow*(db: SqliteDb, query: string,
               params: openArray[DbValue] = []): DbRow =
  let rows = db.queryAll(query, params)
  if rows.len > 0:
    rows[0]
  else:
    initTable[string, string]()
