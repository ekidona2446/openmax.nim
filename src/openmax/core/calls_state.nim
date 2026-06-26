## Central in-memory state for the Calls API + Signaling subsystem.
##
## OpenMAX delegates the actual media relay to an external coturn deployment, so
## this server only has to:
##   * remember the call-tokens it handed out over the mobile protocol (opcode 158)
##   * exchange those tokens for short-lived Calls-API sessions (auth.anonymLogin)
##   * track conversations created via vchat.startConversation
##   * route signaling messages between the participants of a conversation
##
## Everything lives in plain `Table`s guarded by the single-threaded chronos event
## loop (no locks needed: all access happens from async procs on one thread).

import std/[tables, times]

type
  CallToken* = object
    ## A call-token issued to a logged-in user over the mobile protocol.
    token*: string
    userId*: int64
    issuedAtUnix*: int64

  CallsSession* = object
    ## A Calls-API session created by auth.anonymLogin.
    sessionKey*: string
    sessionSecretKey*: string
    userId*: int64
    externalUserId*: string
    createdAtUnix*: int64

  ConversationParticipant* = object
    externalId*: string   ## external_user_id advertised to peers
    internalId*: int64     ## per-conversation participant id used in ServerHello
    userId*: int64         ## real OpenMAX user id
    accepted*: bool        ## calltaker sent accept-call

  Conversation* = object
    id*: string                              ## conversationId (UUID from client)
    callerUserId*: int64
    isVideo*: bool
    createdAtUnix*: int64
    participants*: seq[ConversationParticipant]
    ## one-time signaling tokens -> userId that may join this conversation
    signalingTokens*: Table[string, int64]

  CallsState* = ref object
    tokens*: Table[string, CallToken]        ## call-token string -> CallToken
    sessions*: Table[string, CallsSession]   ## session_key -> CallsSession
    conversations*: Table[string, Conversation]
    ## maps a real userId to the external_user_id used in the Calls API
    externalByUser*: Table[int64, string]
    userByExternal*: Table[string, int64]
    nextExternalSeq*: int64
    nextInternalSeq*: int64

proc newCallsState*(): CallsState =
  CallsState(
    tokens: initTable[string, CallToken](),
    sessions: initTable[string, CallsSession](),
    conversations: initTable[string, Conversation](),
    externalByUser: initTable[int64, string](),
    userByExternal: initTable[string, int64](),
    nextExternalSeq: 1_000_000_000'i64,
    nextInternalSeq: 10_000'i64
  )

proc nowUnix*(): int64 = epochTime().int64

# ---------------------------------------------------------------------------
# External-id mapping: a stable per-user numeric id used across the Calls API.
# ---------------------------------------------------------------------------

proc externalIdFor*(state: CallsState, userId: int64): string =
  if state.externalByUser.hasKey(userId):
    return state.externalByUser[userId]
  inc state.nextExternalSeq
  let ext = $state.nextExternalSeq
  state.externalByUser[userId] = ext
  state.userByExternal[ext] = userId
  ext

proc userIdForExternal*(state: CallsState, externalId: string): int64 =
  state.userByExternal.getOrDefault(externalId, 0'i64)

# ---------------------------------------------------------------------------
# Call-tokens (issued over the mobile protocol, opcode 158).
# ---------------------------------------------------------------------------

proc registerCallToken*(state: CallsState, token: string, userId: int64) =
  if token.len == 0 or userId == 0:
    return
  state.tokens[token] = CallToken(
    token: token,
    userId: userId,
    issuedAtUnix: nowUnix()
  )

proc resolveCallToken*(state: CallsState, token: string, ttlSeconds: int): int64 =
  ## Returns the userId behind a call-token, or 0 if unknown/expired.
  if not state.tokens.hasKey(token):
    return 0
  let entry = state.tokens[token]
  if ttlSeconds > 0 and nowUnix() - entry.issuedAtUnix > ttlSeconds.int64:
    state.tokens.del(token)
    return 0
  entry.userId

# ---------------------------------------------------------------------------
# Calls-API sessions (auth.anonymLogin).
# ---------------------------------------------------------------------------

proc createSession*(state: CallsState, userId: int64,
                    sessionKey, sessionSecretKey, externalUserId: string): CallsSession =
  result = CallsSession(
    sessionKey: sessionKey,
    sessionSecretKey: sessionSecretKey,
    userId: userId,
    externalUserId: externalUserId,
    createdAtUnix: nowUnix()
  )
  state.sessions[sessionKey] = result

proc resolveSession*(state: CallsState, sessionKey: string, ttlSeconds: int): tuple[ok: bool, session: CallsSession] =
  if not state.sessions.hasKey(sessionKey):
    return (false, CallsSession())
  let s = state.sessions[sessionKey]
  if ttlSeconds > 0 and nowUnix() - s.createdAtUnix > ttlSeconds.int64:
    state.sessions.del(sessionKey)
    return (false, CallsSession())
  (true, s)

# ---------------------------------------------------------------------------
# Conversations (vchat.startConversation + signaling).
# ---------------------------------------------------------------------------

proc nextInternalId(state: CallsState): int64 =
  inc state.nextInternalSeq
  state.nextInternalSeq

proc createConversation*(state: CallsState, conversationId: string,
                         callerUserId: int64, calleeUserId: int64,
                         callerExternal, calleeExternal: string,
                         isVideo: bool): Conversation =
  var convo = Conversation(
    id: conversationId,
    callerUserId: callerUserId,
    isVideo: isVideo,
    createdAtUnix: nowUnix(),
    participants: @[],
    signalingTokens: initTable[string, int64]()
  )
  convo.participants.add ConversationParticipant(
    externalId: callerExternal, internalId: state.nextInternalId(),
    userId: callerUserId, accepted: true)            # caller implicitly "accepts"
  if calleeUserId != 0:
    convo.participants.add ConversationParticipant(
      externalId: calleeExternal, internalId: state.nextInternalId(),
      userId: calleeUserId, accepted: false)
  state.conversations[conversationId] = convo
  convo

proc getConversation*(state: CallsState, conversationId: string): tuple[ok: bool, convo: Conversation] =
  if state.conversations.hasKey(conversationId):
    (true, state.conversations[conversationId])
  else:
    (false, Conversation())

proc addSignalingToken*(state: CallsState, conversationId, token: string, userId: int64) =
  if not state.conversations.hasKey(conversationId):
    return
  state.conversations[conversationId].signalingTokens[token] = userId

proc consumeSignalingToken*(state: CallsState, conversationId, token: string): int64 =
  ## Validate (but keep) a signaling token; returns the userId or 0.
  ## Kept rather than consumed so reconnects during a call still work.
  if not state.conversations.hasKey(conversationId):
    return 0
  state.conversations[conversationId].signalingTokens.getOrDefault(token, 0'i64)

proc participantByUser*(convo: Conversation, userId: int64): tuple[ok: bool, p: ConversationParticipant] =
  for p in convo.participants:
    if p.userId == userId:
      return (true, p)
  (false, ConversationParticipant())

proc markAccepted*(state: CallsState, conversationId: string, userId: int64) =
  if not state.conversations.hasKey(conversationId):
    return
  var convo = state.conversations[conversationId]
  for i in 0 ..< convo.participants.len:
    if convo.participants[i].userId == userId:
      convo.participants[i].accepted = true
  state.conversations[conversationId] = convo

proc dropConversation*(state: CallsState, conversationId: string) =
  state.conversations.del(conversationId)
