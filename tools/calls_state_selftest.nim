import std/[strutils]
import openmax/core/calls_state

proc check(cond: bool, msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)
  else:
    echo "ok: ", msg

let st = newCallsState()

# 1. issue a call token for user 42
st.registerCallToken("openmax-call:42:abc", 42)
check st.resolveCallToken("openmax-call:42:abc", 300) == 42, "token resolves to user"
check st.resolveCallToken("nope", 300) == 0, "unknown token -> 0"

# 2. external id mapping is stable
let ext42 = st.externalIdFor(42)
check st.externalIdFor(42) == ext42, "external id stable"
check st.userIdForExternal(ext42) == 42, "reverse external lookup"

# 3. callee user 99 registers external id (as if they logged into calls api)
let ext99 = st.externalIdFor(99)
st.registerCallToken("openmax-call:99:xyz", 99)

# 4. session creation + lookup
let s = st.createSession(42, "sk_1", "ss_1", ext42)
let (ok, sess) = st.resolveSession("sk_1", 3600)
check ok and sess.userId == 42, "session resolves"
check not st.resolveSession("sk_bad", 3600).ok, "bad session -> not ok"

# 5. conversation: caller 42 -> callee 99
let convo = st.createConversation("conv-1", 42, 99, ext42, ext99, false)
check convo.participants.len == 2, "two participants"
st.addSignalingToken("conv-1", "tok-caller", 42)
st.addSignalingToken("conv-1", "tok-callee", 99)
check st.consumeSignalingToken("conv-1", "tok-caller") == 42, "caller signaling token"
check st.consumeSignalingToken("conv-1", "tok-callee") == 99, "callee signaling token"
check st.consumeSignalingToken("conv-1", "tok-bad") == 0, "bad signaling token"

# 6. participant lookup + internal ids distinct
let (f1, p1) = convo.participantByUser(42)
let (f2, p2) = convo.participantByUser(99)
check f1 and f2, "both participants found"
check p1.internalId != p2.internalId, "internal ids distinct"
check p1.accepted, "caller pre-accepted"
check not p2.accepted, "callee not yet accepted"

# 7. mark accepted
st.markAccepted("conv-1", 99)
let (_, convo2) = st.getConversation("conv-1")
let (_, p2b) = convo2.participantByUser(99)
check p2b.accepted, "callee accepted after markAccepted"

# 8. token TTL expiry
st.registerCallToken("expiring", 7)
check st.resolveCallToken("expiring", 0) == 7, "ttl=0 means no expiry"

echo "ALL PASS"
