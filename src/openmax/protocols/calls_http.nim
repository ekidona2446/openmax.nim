import std/[json, strutils, uri]
import chronos, httputils, websock/http/common
import ../core/app_context

proc handleCallsHttp*(app: AppContext, request: HttpRequest): Future[void] {.async.} =
  try:
    if request.meth != HttpMethod.MethodPost:
      await request.sendResponse(Http405, content = "Method Not Allowed")
      return
    
    # Very basic form-urlencoded parser (read up to 16KB)
    var bodyData = newSeq[byte](16384)
    let bytesRead = await request.stream.reader.readOnce(addr bodyData[0], bodyData.len)
    bodyData.setLen(bytesRead)
    let body = cast[string](bodyData)
    
    # In a real app we'd parse application/x-www-form-urlencoded properly.
    # For now, let's just return dummy JSON based on maxcalls docs.
    if "method=auth.anonymLogin" in body:
      let resp = %* {
        "uid": "123456789",
        "session_key": "session_key_abc123",
        "session_secret_key": "session_secret_xyz789",
        "api_server": "https://127.0.0.1",
        "external_user_id": "987654321"
      }
      await request.sendResponse(Http200, content = $resp)
    elif "method=vchat.startConversation" in body:
      let resp = %* {
        "turn_server": {
          "urls": ["turn:turn.openmax.su:3478"],
          "username": "user123",
          "credential": "pass456"
        },
        "stun_server": {
          "urls": ["stun:stun.openmax.su:3478"]
        },
        "endpoint": "wss://127.0.0.1/signaling?token=signaling_token_xyz"
      }
      await request.sendResponse(Http200, content = $resp)
    else:
      await request.sendResponse(Http400, content = "Bad Request")
  except CatchableError as exc:
    await request.sendResponse(Http500, content = "Internal Error")
