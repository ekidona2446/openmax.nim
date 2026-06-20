import msgpack4nim

type
  MsgPackCodecError* = object of CatchableError

proc bytesToString*(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(data[i])

proc stringToBytes*(data: string): seq[byte] =
  result = newSeq[byte](data.len)
  for i in 0 ..< data.len:
    result[i] = byte(data[i])

proc packMapPayload*[T](value: T): seq[byte] {.raises: [MsgPackCodecError].} =
  try:
    var stream = MsgStream.init("", MSGPACK_OBJ_TO_MAP)
    stream.pack(value)
    stringToBytes(stream.data)
  except Exception as exc:
    raise newException(MsgPackCodecError, exc.msg)

proc unpackMapPayload*[T](data: openArray[byte], _: typedesc[T]): T {.raises: [MsgPackCodecError].} =
  try:
    var stream = MsgStream.init(bytesToString(data), MSGPACK_OBJ_TO_MAP)
    result = stream.unpack(T)
  except Exception as exc:
    raise newException(MsgPackCodecError, exc.msg)

proc nilPayload*(): seq[byte] =
  @[0xC0'u8]
