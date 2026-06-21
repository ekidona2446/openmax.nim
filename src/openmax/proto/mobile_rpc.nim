import chronos
import msgpack4nim
import ./mobile_frame
import ./msgpack_codec
import ./lz4_block
import ../core/opcodes

type
  ErrorPayload* = object
    localizedMessage*: string
    error*: string
    message*: string
    title*: string

proc responseFrame*(request: MobileFrame,
                    cmd: uint8,
                    opcode: uint16,
                    payload: seq[byte]): MobileFrame =
  MobileFrame(
    header: MobileHeader(
      ver: request.header.ver,
      cmd: cmd,
      seq: request.header.seq,
      opcode: opcode,
      compressionFlag: DefaultLz4CompressionFlag,
      payloadLength: payload.len
    ),
    payload: payload
  )

proc sendResponseBytes*(transp: MobileTransport,
                        request: MobileFrame,
                        cmd: uint8,
                        opcode: uint16,
                        payload: seq[byte]): Future[void] {.async.} =
  await transp.writeFrame(responseFrame(request, cmd, opcode, payload))

proc sendResponseObject*[T](transp: MobileTransport,
                            request: MobileFrame,
                            cmd: uint8,
                            opcode: uint16,
                            payload: T): Future[void] {.async.} =
  await sendResponseBytes(transp, request, cmd, opcode, packMapPayload(payload))

proc sendNilResponse*(transp: MobileTransport,
                      request: MobileFrame,
                      cmd: uint8,
                      opcode: uint16): Future[void] {.async.} =
  await sendResponseBytes(transp, request, cmd, opcode, nilPayload())

proc sendErrorResponse*(transp: MobileTransport,
                        request: MobileFrame,
                        opcode: uint16,
                        payload: ErrorPayload): Future[void] {.async.} =
  await sendResponseObject(transp, request, CmdErr, opcode, payload)
