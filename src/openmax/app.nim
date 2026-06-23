import std/[logging, strformat, strutils, os]
import chronos
import ./config/loader
import ./core/protocols
import ./core/app_context
import ./db/store
import ./protocols/profiles
import ./session/registry
import ./transport/listener

proc parseLogLevel(name: string): Level =
  case name.toLowerAscii()
  of "debug": lvlDebug
  of "info": lvlInfo
  of "warn", "warning": lvlWarn
  of "error": lvlError
  of "fatal": lvlFatal
  else: lvlDebug

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

proc setupLogging(levelName: string) =
  addHandler(newConsoleLogger(parseLogLevel(levelName), fmtStr = verboseFmtStr))

proc logProfileSummary() =
  safeInfo(&"[profile] {OnemeProfile.name} namespace={OnemeProfile.session_namespace}")
  safeInfo(&"[profile] {TamtamProfile.name} namespace={TamtamProfile.session_namespace}")

proc run*(configPath: string): Future[void] {.async.} =
  let config = loadConfig(configPath)
  setupLogging(config.server.log_level)

  let projectDir = parentDir(configPath.absolutePath())
  let schemaPath = projectDir / "sql" / "tables.sql"
  let database = openDatabase(config.database, projectDir)
  let app = newAppContext(config, database)

  safeInfo(&"[bootstrap] config loaded from {configPath}")
  safeInfo(&"[bootstrap] bind host = {config.server.host}")
  safeInfo(&"[bootstrap] dualstack mode = {config.server.dualstack_mode}")
  safeInfo(&"[bootstrap] database kind = {config.database.kind}")
  safeInfo(&"[bootstrap] sqlite schema initialized from {schemaPath}")
  safeInfo(&"[bootstrap] tls enabled = {config.tls.enabled}")
  logProfileSummary()

  let registry = newSessionRegistry()
  safeInfo(&"[bootstrap] session registry initialized, connected users = {registry.connectedUsersCount()}")

  let listeners = buildListenerSpecs(config)
  if listeners.len == 0:
    safeWarn("[bootstrap] no listeners enabled in config")
    return

  for spec in listeners:
    safeInfo(&"[bootstrap] configured listener: {spec.describe()}")
    asyncSpawn newListenerRuntime(app, spec).start()

  safeInfo("[bootstrap] app loop started")
  while true:
    await sleepAsync(1.hours)
