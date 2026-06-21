import std/[strformat]
import chronos
import ../tls/wolf_tls
import ./lz4_block

const
  MobileHeaderSize* = 10
  DefaultMaxPayloadSize* = 1_048_576
  DefaultMaxDecompressedSize* = 1_048_576
  WolfEncryptedReadChunk = 1


type
  MobileFrameError* = object of CatchableError

  MobileHeader* = object
    ver*: uint8
    cmd*: uint8
    seq*: uint16
    opcode*: uint16
    compressionFlag*: uint8
    payloadLength*: int

  MobileFrame* = object
    header*: MobileHeader
    payload*: seq[byte]

  MobileTransport* = ref object
    raw*: StreamTransport
    wolf*: WolfTlsSession
    tls*: bool
    handshakeDone*: bool

proc readUint16Be(data: openArray[byte], offset: int): uint16 =
  (uint16(data[offset]) shl 8) or uint16(data[offset + 1])

proc readUint32Be(data: openArray[byte], offset: int): uint32 =
  (uint32(data[offset]) shl 24) or
  (uint32(data[offset + 1]) shl 16) or
  (uint32(data[offset + 2]) shl 8) or
  uint32(data[offset + 3])

proc writeUint16Be(value: uint16, target: var openArray[byte], offset: int) =
  target[offset] = byte((value shr 8) and 0xFF'u16)
  target[offset + 1] = byte(value and 0xFF'u16)

proc writeUint32Be(value: uint32, target: var openArray[byte], offset: int) =
  target[offset] = byte((value shr 24) and 0xFF'u32)
  target[offset + 1] = byte((value shr 16) and 0xFF'u32)
  target[offset + 2] = byte((value shr 8) and 0xFF'u32)
  target[offset + 3] = byte(value and 0xFF'u32)

proc decodeHeader*(data: openArray[byte], maxPayloadSize = DefaultMaxPayloadSize): MobileHeader =
  if data.len < MobileHeaderSize:
    raise newException(MobileFrameError, "Mobile header is shorter than 10 bytes")

  let packedLen = readUint32Be(data, 6)
  let payloadLength = int(packedLen and 0x00FF_FFFF'u32)
  let compressionFlag = uint8((packedLen shr 24) and 0xFF'u32)

  if payloadLength > maxPayloadSize:
    raise newException(
      MobileFrameError,
      &"Payload too large: {payloadLength} bytes > {maxPayloadSize}"
    )

  MobileHeader(
    ver: uint8(data[0]),
    cmd: uint8(data[1]),
    seq: readUint16Be(data, 2),
    opcode: readUint16Be(data, 4),
    compressionFlag: compressionFlag,
    payloadLength: payloadLength
  )

proc encodeHeader*(header: MobileHeader): array[MobileHeaderSize, byte] =
  if header.payloadLength < 0:
    raise newException(MobileFrameError, "Payload length can not be negative")

  if header.payloadLength > 0x00FF_FFFF:
    raise newException(MobileFrameError, "Payload length exceeds 24-bit field")

  let packedLen =
    (uint32(header.compressionFlag) shl 24) or
    (uint32(header.payloadLength) and 0x00FF_FFFF'u32)

  result[0] = byte(header.ver)
  result[1] = byte(header.cmd)
  writeUint16Be(header.seq, result, 2)
  writeUint16Be(header.opcode, result, 4)
  writeUint32Be(packedLen, result, 6)

proc packFrame*(header: MobileHeader, payload: openArray[byte]): seq[byte] =
  var wirePayload = @payload
  var wireCompressionFlag = header.compressionFlag

  if header.compressionFlag != 0 and payload.len > 0:
    try:
      let compressed = maybeCompressBlock(payload, header.compressionFlag)
      wireCompressionFlag = compressed.compressionFlag
      wirePayload = compressed.payload
    except Lz4Error as exc:
      raise newException(MobileFrameError, exc.msg)
  else:
    wireCompressionFlag = 0

  let wireHeader = MobileHeader(
    ver: header.ver,
    cmd: header.cmd,
    seq: header.seq,
    opcode: header.opcode,
    compressionFlag: wireCompressionFlag,
    payloadLength: wirePayload.len
  )

  result = newSeq[byte](MobileHeaderSize + wirePayload.len)
  let headerBytes = encodeHeader(wireHeader)

  for i in 0 ..< MobileHeaderSize:
    result[i] = headerBytes[i]

  for i in 0 ..< wirePayload.len:
    result[MobileHeaderSize + i] = wirePayload[i]

proc decodeWirePayload(header: MobileHeader,
                       wirePayload: openArray[byte],
                       maxDecompressedSize = DefaultMaxDecompressedSize): seq[byte] =
  if header.compressionFlag == 0:
    return @wirePayload

  try:
    decompressBlock(wirePayload, maxDecompressedSize)
  except Lz4Error as exc:
    raise newException(MobileFrameError, exc.msg)

proc unpackFrame*(data: openArray[byte],
                  maxPayloadSize = DefaultMaxPayloadSize,
                  maxDecompressedSize = DefaultMaxDecompressedSize): MobileFrame =
  let header = decodeHeader(data, maxPayloadSize)
  let requiredLength = MobileHeaderSize + header.payloadLength

  if data.len < requiredLength:
    raise newException(
      MobileFrameError,
      &"Incomplete frame: need {requiredLength} bytes, got {data.len}"
    )

  result.header = header
  result.payload = decodeWirePayload(
    header,
    data.toOpenArray(MobileHeaderSize, requiredLength - 1),
    maxDecompressedSize
  )

proc newPlainMobileTransport*(transp: StreamTransport): MobileTransport =
  MobileTransport(raw: transp, tls: false, handshakeDone: true)

proc newTlsMobileTransport*(transp: StreamTransport, ctx: WolfTlsContext): MobileTransport =
  MobileTransport(raw: transp, wolf: newWolfTlsSession(ctx), tls: true, handshakeDone: false)

proc flushWolfOutput(transp: MobileTransport): Future[void] {.async: (raises: [TransportError, CancelledError]).} =
  let outData = transp.wolf.takeOutput()
  if outData.len > 0:
    discard await transp.raw.write(outData)

proc feedEncryptedByte(transp: MobileTransport): Future[void] {.async: (raises: [TransportError, CancelledError]).} =
  var b = newSeq[byte](WolfEncryptedReadChunk)
  await transp.raw.readExactly(addr b[0], b.len)
  transp.wolf.feed(b)

proc ensureHandshake(transp: MobileTransport): Future[void] {.
  async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  if not transp.tls or transp.handshakeDone:
    return
  while true:
    let rc = transp.wolf.acceptStep()
    await transp.flushWolfOutput()
    if rc == 1:
      transp.handshakeDone = true
      return
    if rc < 0:
      raise newException(WolfTlsError, &"wolfSSL_accept failed: {-rc}")
    await transp.feedEncryptedByte()

proc readPlainN(transp: MobileTransport, nbytes: int): Future[seq[byte]] {.
  async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  await transp.ensureHandshake()
  result = newSeq[byte](nbytes)
  var offset = 0
  while offset < nbytes:
    var tmp = newSeq[byte](nbytes - offset)
    let rc = transp.wolf.readPlainStep(tmp)
    await transp.flushWolfOutput()
    if rc > 0:
      for i in 0 ..< rc:
        result[offset + i] = tmp[i]
      offset += rc
    elif rc < 0:
      if -rc == WolfSslErrorZeroReturn:
        raise newException(WolfTlsClosedError, "TLS peer closed connection")
      raise newException(WolfTlsError, &"wolfSSL_read failed: {-rc}")
    else:
      await transp.feedEncryptedByte()

proc writePlainBytes(transp: MobileTransport, src: seq[byte]) {.
  async: (raises: [TransportError, CancelledError, WolfTlsError]).} =
  await transp.ensureHandshake()
  var offset = 0
  while offset < src.len:
    let rc = transp.wolf.writePlainStep(src.toOpenArray(offset, src.len - 1))
    await transp.flushWolfOutput()
    if rc > 0:
      offset += rc
    elif rc < 0:
      raise newException(WolfTlsError, &"wolfSSL_write failed: {-rc}")
    else:
      await transp.feedEncryptedByte()

proc readFrame*(transp: StreamTransport,
                maxPayloadSize = DefaultMaxPayloadSize,
                maxDecompressedSize = DefaultMaxDecompressedSize): Future[MobileFrame] {.
                  async: (raises: [MobileFrameError, TransportError, CancelledError]).} =
  var headerBytes = newSeq[byte](MobileHeaderSize)
  await transp.readExactly(addr headerBytes[0], headerBytes.len)

  let header = decodeHeader(headerBytes, maxPayloadSize)
  result.header = header

  if header.payloadLength == 0:
    result.payload = @[]
    return

  var wirePayload = newSeq[byte](header.payloadLength)
  await transp.readExactly(addr wirePayload[0], wirePayload.len)
  result.payload = decodeWirePayload(header, wirePayload, maxDecompressedSize)

proc readFrame*(transp: MobileTransport,
                maxPayloadSize = DefaultMaxPayloadSize,
                maxDecompressedSize = DefaultMaxDecompressedSize): Future[MobileFrame] {.
                  async: (raises: [MobileFrameError, TransportError, WolfTlsError, CancelledError]).} =
  if not transp.tls:
    return await transp.raw.readFrame(maxPayloadSize, maxDecompressedSize)

  let headerBytes = await transp.readPlainN(MobileHeaderSize)

  let header = decodeHeader(headerBytes, maxPayloadSize)
  result.header = header

  if header.payloadLength == 0:
    result.payload = @[]
    return

  let wirePayload = await transp.readPlainN(header.payloadLength)
  result.payload = decodeWirePayload(header, wirePayload, maxDecompressedSize)

proc writeFrame*(transp: StreamTransport, frame: MobileFrame): Future[void] {.async.} =
  let packed = packFrame(frame.header, frame.payload)
  discard await transp.write(packed)

proc writeFrame*(transp: MobileTransport, frame: MobileFrame): Future[void] {.async.} =
  let packed = packFrame(frame.header, frame.payload)
  if not transp.tls:
    discard await transp.raw.write(packed)
  else:
    await transp.writePlainBytes(packed)

proc closeWait*(transp: MobileTransport): Future[void] {.async: (raises: []).} =
  if transp.tls and not transp.wolf.isNil:
    transp.wolf.close()
  await transp.raw.closeWait()
