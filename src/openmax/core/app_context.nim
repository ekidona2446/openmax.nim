import std/[tables, sequtils]
import chronos
import ../config/types
import ../db/store

type
  AppContext* = ref object
    config*: AppConfig
    db*: AppDatabase
    clientsByUser*: Table[int64, seq[StreamTransport]]

proc newAppContext*(config: AppConfig, db: AppDatabase): AppContext =
  AppContext(
    config: config,
    db: db,
    clientsByUser: initTable[int64, seq[StreamTransport]]()
  )

proc attachClient*(app: AppContext, userId: int64, transp: StreamTransport) =
  if userId == 0 or transp.isNil:
    return
  var clients = app.clientsByUser.getOrDefault(userId, @[])
  if clients.allIt(it != transp):
    clients.add transp
  app.clientsByUser[userId] = clients

proc detachClient*(app: AppContext, userId: int64, transp: StreamTransport) =
  if userId == 0 or transp.isNil or not app.clientsByUser.hasKey(userId):
    return
  let clients = app.clientsByUser[userId].filterIt(it != transp)
  if clients.len == 0:
    app.clientsByUser.del(userId)
  else:
    app.clientsByUser[userId] = clients

proc transportsForUser*(app: AppContext, userId: int64): seq[StreamTransport] =
  app.clientsByUser.getOrDefault(userId, @[])
