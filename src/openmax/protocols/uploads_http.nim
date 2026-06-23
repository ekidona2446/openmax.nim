import std/[json, strutils, strformat, random]
import chronos, httputils, websock/http/common
import ../core/app_context
import ../core/opcodes
import ../proto/mobile_frame
import ../proto/mobile_rpc
import ../proto/msgpack_codec
import ./auth_utils

const MaxUploadSinkBytes = 64 * 1024 * 1024

proc bytes(data: string): seq[byte] =
  result = newSeq[byte](data.len)
  for i, ch in data:
    result[i] = byte(ch)

proc seqToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc findHeaderEnd(data: string): int =
  let crlf = data.find("\r\n\r\n")
  if crlf >= 0: crlf else: data.find("\n\n")

proc headerTermLen(data: string, pos: int): int =
  if pos >= 0 and pos + 3 < data.len and data[pos .. pos + 3] == "\r\n\r\n": 4 else: 2

proc parseContentLength(headers: string): int =
  for line in headers.splitLines():
    let p = line.find(':')
    if p <= 0: continue
    if line[0 ..< p].strip().toLowerAscii() == "content-length":
      try: return parseInt(line[p + 1 .. ^1].strip())
      except ValueError: return 0
  0

proc httpResponse(status: int, content: string): string =
  let reason =
    case status
    of 200: "OK"
    of 404: "Not Found"
    of 413: "Payload Too Large"
    else: "Error"
  &"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {content.len}\r\nConnection: close\r\n\r\n{content}"

proc queryParam(query, key: string): string =
  for part in query.split('&'):
    if part.len == 0: continue
    let eq = part.find('=')
    let k = if eq >= 0: part[0 ..< eq] else: part
    if k == key:
      return if eq >= 0: part[eq + 1 .. ^1] else: ""
  ""

proc drainBody(request: HttpRequest): Future[int] {.async.} =
  ## Read and discard uploaded bytes. This makes aiohttp finish the POST and
  ## gives us a place to add persistent storage later.
  var total = 0
  var buf = newSeq[byte](64 * 1024)
  while true:
    let n = await request.stream.reader.readOnce(addr buf[0], buf.len)
    if n <= 0:
      break
    total += n
    if total > MaxUploadSinkBytes:
      break
  total

proc dummyRequest(opcode: uint16): MobileFrame =
  MobileFrame(
    header: MobileHeader(
      ver: ProtoVer,
      cmd: 0'u8,
      seq: 0'u16,
      opcode: opcode,
      compressionFlag: 0'u8,
      payloadLength: 0
    ),
    payload: @[]
  )

proc notifyUploadReady(app: AppContext, userId: int64, payload: JsonNode) {.async: (raises: []).} =
  if userId == 0:
    return
  let bytes =
    try:
      packJsonPayload(payload)
    except MsgPackCodecError:
      return
  let frame = dummyRequest(NotifAttachOpcode)
  for client in app.transportsForUser(userId):
    try:
      await client.sendResponseBytes(frame, 0'u8, NotifAttachOpcode, bytes)
    except CatchableError:
      discard

proc handleUploadPath*(app: AppContext, path, query: string): Future[tuple[status: int, content: string]] {.async.} =
  let userId =
    try: parseBiggestInt(queryParam(query, "userId")).int64
    except ValueError: 0'i64
  let token = queryParam(query, "token")

  if path.endsWith("/photo"):
    let photoId = queryParam(query, "photoIds")
    let photoToken = if token.len > 0: token else: generateRandomString(48)
    return (200, $ (%*{"photos": {photoId: {"token": photoToken}}}))
  elif path.endsWith("/file"):
    let fileId =
      try: parseBiggestInt(queryParam(query, "fileId")).int64
      except ValueError: 0'i64
    asyncSpawn notifyUploadReady(app, userId, %*{"fileId": fileId})
    return (200, $ (%*{"ok": true}))
  elif path.endsWith("/video"):
    let videoId =
      try: parseBiggestInt(queryParam(query, "videoId")).int64
      except ValueError: 0'i64
    asyncSpawn notifyUploadReady(app, userId, %*{"videoId": videoId})
    return (200, $ (%*{"ok": true}))
  else:
    return (404, $ (%*{"error": "not found"}))

proc handleUploadHttp*(app: AppContext, request: HttpRequest): Future[void] {.async.} =
  discard await drainBody(request)
  let (status, content) = await app.handleUploadPath(request.uri.path, request.uri.query)
  await request.sendResponse(if status == 200: Http200 elif status == 404: Http404 else: Http500, content = content)

proc handleUploadMobile*(app: AppContext,
                         transp: MobileTransport,
                         firstBytes: seq[byte]): Future[void] {.async.} =
  ## Parse a small HTTP/1.1 upload request over the same plaintext channel as
  ## the mobile TCP protocol. Works both before and after wolfSSL unwrap.
  var raw = seqToString(firstBytes)
  var headerEnd = findHeaderEnd(raw)
  while headerEnd < 0 and raw.len < 64 * 1024:
    raw.add seqToString(await transp.readPlainBytes(1))
    headerEnd = findHeaderEnd(raw)

  if headerEnd < 0:
    await transp.writePlainBytes(bytes(httpResponse(413, $ (%*{"error": "headers too large"}))))
    return

  let termLen = headerTermLen(raw, headerEnd)
  let headers = raw[0 ..< headerEnd]
  let lines = headers.splitLines()
  if lines.len == 0:
    await transp.writePlainBytes(bytes(httpResponse(404, $ (%*{"error": "bad request"}))))
    return

  let parts = lines[0].split(' ')
  if parts.len < 2:
    await transp.writePlainBytes(bytes(httpResponse(404, $ (%*{"error": "bad request"}))))
    return

  let target = parts[1]
  let qpos = target.find('?')
  let path = if qpos >= 0: target[0 ..< qpos] else: target
  let query = if qpos >= 0 and qpos + 1 < target.len: target[qpos + 1 .. ^1] else: ""
  let contentLen = parseContentLength(headers)
  let alreadyBody = max(0, raw.len - headerEnd - termLen)
  var remaining = max(0, contentLen - alreadyBody)

  if contentLen > MaxUploadSinkBytes:
    await transp.writePlainBytes(bytes(httpResponse(413, $ (%*{"error": "upload too large"}))))
    return

  while remaining > 0:
    let chunk = await transp.readPlainBytes(min(4096, remaining))
    remaining -= chunk.len

  let (status, content) = await app.handleUploadPath(path, query)
  await transp.writePlainBytes(bytes(httpResponse(status, content)))

proc uploadPort*(app: AppContext, protocolName: string): int =
  ## Upload URLs use the same public API port as the binary TCP protocol.
  ## The TCP listener sniffs the first plaintext byte and routes HTTP methods
  ## to the upload sink, while normal mobile frames continue through MsgPack.
  if protocolName == "tamtam": app.config.protocols.tamtam_tcp_port
  else: app.config.protocols.oneme_tcp_port

proc uploadBaseUrl*(app: AppContext, protocolName: string): string =
  let host = app.config.server.host.strip(chars = {'[', ']'})
  let displayHost = if host.contains(":"): "[" & host & "]" else: host
  let port = app.uploadPort(protocolName)
  let scheme = if app.config.tls.enabled: "https" else: "http"
  &"{scheme}://{displayHost}:{port}/upload"

proc uploadRequestPayload*(app: AppContext, protocolName, kind: string, userId: int64): JsonNode =
  let id = (rand(2_000_000_000 - 1000) + 1000).int64
  let token = generateRandomString(48)
  let base = app.uploadBaseUrl(protocolName)
  case kind
  of "photo":
    %*{"url": &"{base}/photo?photoIds={id}&userId={userId}&token={token}"}
  of "video":
    %*{"info": [{"url": &"{base}/video?videoId={id}&userId={userId}&token={token}", "videoId": id, "token": token}]}
  else:
    %*{"info": [{"url": &"{base}/file?fileId={id}&userId={userId}&token={token}", "fileId": id, "token": token}]}
