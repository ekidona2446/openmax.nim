import std/[tables, strutils, times, sequtils]
import ../core/protocols

type
  UserId* = int64
  SessionId* = string

  SessionInfo* = object
    id*: SessionId
    protocol*: ProtocolKind
    transport*: TransportKind
    peer*: string
    connected_at_unix*: int64

  ClientState* = object
    user_id*: UserId
    sessions*: seq[SessionInfo]

  SessionRegistry* = ref object
    clients_by_user*: Table[UserId, ClientState]

proc newSessionRegistry*(): SessionRegistry =
  SessionRegistry(clients_by_user: initTable[UserId, ClientState]())

proc nowUnix*(): int64 =
  epochTime().int64

proc makeSessionId*(protocol: ProtocolKind, transport: TransportKind,
                    user_id: UserId, peer: string): SessionId =
  let normalizedPeer = peer.replace(":", "_")
  $protocol & ":" & $transport & ":" & $user_id & ":" & normalizedPeer & ":" & $nowUnix()

proc attach*(registry: SessionRegistry, user_id: UserId, session: SessionInfo) =
  var state = registry.clients_by_user.getOrDefault(
    user_id,
    ClientState(user_id: user_id, sessions: @[])
  )

  state.sessions.add session
  registry.clients_by_user[user_id] = state

proc detach*(registry: SessionRegistry, user_id: UserId, session_id: SessionId) =
  if not registry.clients_by_user.hasKey(user_id):
    return

  var state = registry.clients_by_user[user_id]
  state.sessions = state.sessions.filterIt(it.id != session_id)

  if state.sessions.len == 0:
    registry.clients_by_user.del(user_id)
  else:
    registry.clients_by_user[user_id] = state

proc sessionsOf*(registry: SessionRegistry, user_id: UserId): seq[SessionInfo] =
  registry.clients_by_user.getOrDefault(
    user_id,
    ClientState(user_id: user_id, sessions: @[])
  ).sessions

proc connectedUsersCount*(registry: SessionRegistry): int =
  registry.clients_by_user.len
