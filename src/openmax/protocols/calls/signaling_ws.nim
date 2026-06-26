## Signaling API — WebSocket service for active calls.
##
## Implements the message flow documented by the maxcalls reference
## (icyfalc0n/maxcalls @ master, docs/api/singaling.md):
##
##   server -> client : ServerHello (participants + external/internal id map)
##   client -> server : accept-call            (calltaker accepts)
##   client -> server : transmit-data          (relayed to a peer)
##   server -> client : transmitted-data       (notification, relayed payload)
##   server <-> client: ping / pong            (raw text heartbeat)
##
## The endpoint + a one-time token are minted by vchat.startConversation
## (see calls_http.nim). A connection is bound to (conversationId, userId);
## transmit-data is routed by the recipient's *internal* participant id.

import std/[json, strutils, tables, logging]
import chronos
import websock/websock
import ../../core/app_context
import ../../core/calls_state

type
  SignalingConn = ref object
    ws: WSSession
    userId: int64
    conversationId: string
    internalId: int64

  SignalingHub* = ref object
    ## conversationId -> (userId -> connection)
    rooms: Table[string, Table[int64, SignalingConn]]

var hub {.threadvar.}: SignalingHub

proc getHub(): SignalingHub =
  if hub.isNil:
    hub = SignalingHub(rooms: initTable[string, Table[int64, SignalingConn]]())
  hub

proc safeInfo(message: string) =
  try: info message
  except Exception: discard

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(data[i])

# ---------------------------------------------------------------------------
# Room bookkeeping
# ---------------------------------------------------------------------------

proc register(conn: SignalingConn) =
  let h = getHub()
  if not h.rooms.hasKey(conn.conversationId):
    h.rooms[conn.conversationId] = initTable[int64, SignalingConn]()
  h.rooms[conn.conversationId][conn.userId] = conn

proc unregister(conn: SignalingConn) =
  let h = getHub()
  if h.rooms.hasKey(conn.conversationId):
    h.rooms[conn.conversationId].del(conn.userId)
    if h.rooms[conn.conversationId].len == 0:
      h.rooms.del(conn.conversationId)

proc connByInternalId(conversationId: string, internalId: int64): SignalingConn =
  let h = getHub()
  if h.rooms.hasKey(conversationId):
    for _, c in h.rooms[conversationId]:
      if c.internalId == internalId:
        return c
  nil

# ---------------------------------------------------------------------------
# Outbound message builders
# ---------------------------------------------------------------------------

proc serverHelloJson(convo: Conversation): JsonNode =
  var participants = newJArray()
  for p in convo.participants:
    participants.add %*{
      "externalId": {"id": p.externalId},
      "id": p.internalId
    }
  %*{"conversation": {"participants": participants}}

proc transmittedDataJson(data: JsonNode): JsonNode =
  %*{
    "type": "notification",
    "notification": "transmitted-data",
    "data": data
  }

proc sendJson(conn: SignalingConn, payload: JsonNode): Future[void] {.async.} =
  await conn.ws.send($payload)

# ---------------------------------------------------------------------------
# Inbound command handling
# ---------------------------------------------------------------------------

proc handleCommand(app: AppContext, conn: SignalingConn, msg: JsonNode): Future[void] {.async.} =
  let command = msg{"command"}.getStr("")
  case command
  of "accept-call":
    app.calls.markAccepted(conn.conversationId, conn.userId)
    safeInfo("[calls/sig] accept-call conversation=" & conn.conversationId &
             " user=" & $conn.userId)
  of "transmit-data":
    let targetInternal = msg{"participantId"}.getInt(0).int64
    let data = if msg.hasKey("data"): msg["data"] else: newJNull()
    let target = connByInternalId(conn.conversationId, targetInternal)
    if target.isNil:
      safeInfo("[calls/sig] transmit-data to offline participant=" &
               $targetInternal & " conversation=" & conn.conversationId)
      return
    try:
      await target.sendJson(transmittedDataJson(data))
    except CatchableError as exc:
      safeInfo("[calls/sig] failed to relay transmit-data: " & exc.msg)
  else:
    safeInfo("[calls/sig] ignoring unknown command=" & command)

# ---------------------------------------------------------------------------
# Entry point (called from the listener after the WS upgrade)
# ---------------------------------------------------------------------------

proc handleSignalingWebSocket*(app: AppContext, ws: WSSession,
                               conversationId, token: string,
                               peer: string): Future[void] {.async.} =
  if not app.callsEnabled():
    await ws.close()
    return

  let (ok, convo) = app.calls.getConversation(conversationId)
  if not ok:
    safeInfo("[calls/sig] reject: unknown conversation=" & conversationId & " peer=" & peer)
    await ws.close()
    return

  let userId = app.calls.consumeSignalingToken(conversationId, token)
  if userId == 0:
    safeInfo("[calls/sig] reject: bad signaling token conversation=" & conversationId & " peer=" & peer)
    await ws.close()
    return

  let (found, participant) = convo.participantByUser(userId)
  if not found:
    safeInfo("[calls/sig] reject: user not a participant conversation=" & conversationId)
    await ws.close()
    return

  let conn = SignalingConn(
    ws: ws,
    userId: userId,
    conversationId: conversationId,
    internalId: participant.internalId
  )
  conn.register()
  safeInfo("[calls/sig] connected conversation=" & conversationId &
           " user=" & $userId & " internalId=" & $participant.internalId & " peer=" & peer)

  try:
    # 1. ServerHello first, exactly as the spec requires. Re-fetch so that
    #    participants added after this socket's token was minted are included.
    let (stillOk, liveConvo) = app.calls.getConversation(conversationId)
    await conn.sendJson(serverHelloJson(if stillOk: liveConvo else: convo))

    # 2. Message loop with raw ping/pong + JSON commands.
    while ws.readyState != ReadyState.Closed:
      let raw = bytesToString(await ws.recvMsg())
      if ws.readyState == ReadyState.Closed:
        break
      let trimmed = raw.strip()
      if trimmed.len == 0:
        continue
      if trimmed == "ping":
        await ws.send("pong")
        continue
      let msg =
        try:
          parseJson(trimmed)
        except CatchableError:
          continue                      # spec: ignore non-JSON, non-ping frames
      if msg.kind == JObject:
        await handleCommand(app, conn, msg)
  except WebSocketError as exc:
    safeInfo("[calls/sig] websocket error conversation=" & conversationId & ": " & exc.msg)
  except CatchableError as exc:
    safeInfo("[calls/sig] handler error conversation=" & conversationId & ": " & exc.msg)
  finally:
    conn.unregister()
    safeInfo("[calls/sig] disconnected conversation=" & conversationId & " user=" & $userId)
