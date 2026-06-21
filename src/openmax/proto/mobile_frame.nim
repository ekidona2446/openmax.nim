import std/[strformat]
import chronos
import chronos/streams/tlsstream
import ./lz4_block

const
  MobileHeaderSize* = 10
  DefaultMaxPayloadSize* = 1_048_576
  DefaultMaxDecompressedSize* = 1_048_576


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
    reader*: AsyncStreamReader
    writer*: AsyncStreamWriter
    tlsPrivateKey*: TLSPrivateKey
    tlsCertificate*: TLSCertificate
    tlsStream*: TLSAsyncStream
    tls*: bool

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
  MobileTransport(raw: transp, tls: false)

proc newTlsMobileTransport*(transp: StreamTransport,
                            privateKey: TLSPrivateKey,
                            certificate: TLSCertificate): MobileTransport =
  result = MobileTransport(
    raw: transp,
    tlsPrivateKey: privateKey,
    tlsCertificate: certificate,
    tls: true
  )
  let tlsStream = newTLSServerAsyncStream(
    newAsyncStreamReader(transp),
    newAsyncStreamWriter(transp),
    result.tlsPrivateKey,
    result.tlsCertificate
  )
  result.tlsStream = tlsStream
  result.reader = tlsStream.reader
  result.writer = tlsStream.writer

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
                  async: (raises: [MobileFrameError, TransportError, AsyncStreamError, CancelledError]).} =
  if not transp.tls:
    return await transp.raw.readFrame(maxPayloadSize, maxDecompressedSize)

  var headerBytes = newSeq[byte](MobileHeaderSize)
  await transp.reader.readExactly(addr headerBytes[0], headerBytes.len)

  let header = decodeHeader(headerBytes, maxPayloadSize)
  result.header = header

  if header.payloadLength == 0:
    result.payload = @[]
    return

  var wirePayload = newSeq[byte](header.payloadLength)
  await transp.reader.readExactly(addr wirePayload[0], wirePayload.len)
  result.payload = decodeWirePayload(header, wirePayload, maxDecompressedSize)

proc writeFrame*(transp: StreamTransport, frame: MobileFrame): Future[void] {.async.} =
  let packed = packFrame(frame.header, frame.payload)
  discard await transp.write(packed)

proc writeFrame*(transp: MobileTransport, frame: MobileFrame): Future[void] {.async.} =
  let packed = packFrame(frame.header, frame.payload)
  if not transp.tls:
    discard await transp.raw.write(packed)
  else:
    await transp.writer.write(addr packed[0], packed.len)

proc closeWait*(transp: MobileTransport): Future[void] {.async: (raises: []).} =
  await transp.raw.closeWait()
