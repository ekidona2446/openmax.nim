import chronos
import chronos/streams/asyncstream
import ./wolf_tls

const
  WolfPlainReadChunk = 16 * 1024
  WolfReaderBufferSize = 64 * 1024

type
  WolfStreamState = ref object
    conn: WolfTlsConnection

proc asReadError(exc: ref CatchableError): ref AsyncStreamReadError =
  newException(AsyncStreamReadError, "WolfSSL read failed: " & exc.msg)

proc asWriteError(exc: ref CatchableError): ref AsyncStreamWriteError =
  newException(AsyncStreamWriteError, "WolfSSL write failed: " & exc.msg)

proc wolfReaderLoop(rstream: AsyncStreamReader) {.async: (raises: []).} =
  let state = getUserData[WolfStreamState](rstream)
  try:
    while rstream.state == AsyncStreamState.Running:
      let plain = await state.conn.readPlainSome(WolfPlainReadChunk)
      if plain.len == 0:
        rstream.state = AsyncStreamState.Finished
        break
      await rstream.buffer.upload(unsafeAddr plain[0], plain.len)
  except CancelledError:
    rstream.state = AsyncStreamState.Stopped
  except WolfTlsClosedError:
    rstream.state = AsyncStreamState.Finished
  except CatchableError as exc:
    rstream.error = asReadError(exc)
    rstream.state = AsyncStreamState.Error
  finally:
    if not rstream.buffer.isNil:
      rstream.buffer.forget()

proc writeItemToSeq(item: WriteItem): seq[byte] =
  result = newSeq[byte](item.size)
  if item.size > 0:
    copyOut(addr result[0], item, item.size)

proc wolfWriterLoop(wstream: AsyncStreamWriter) {.async: (raises: []).} =
  let state = getUserData[WolfStreamState](wstream)
  try:
    while wstream.state == AsyncStreamState.Running:
      var item = await wstream.queue.get()
      if item.size == 0:
        item.future.complete()
        wstream.state = AsyncStreamState.Finished
        break
      let plain = writeItemToSeq(item)
      try:
        await state.conn.writePlain(plain)
        item.future.complete()
      except CancelledError as exc:
        item.future.fail(exc)
        raise exc
      except CatchableError as exc:
        item.future.fail(asWriteError(exc))
        raise exc
  except CancelledError:
    wstream.state = AsyncStreamState.Stopped
  except WolfTlsClosedError:
    wstream.state = AsyncStreamState.Finished
  except CatchableError as exc:
    wstream.error = asWriteError(exc)
    wstream.state = AsyncStreamState.Error
  finally:
    discard

proc newWolfAsyncStream*(raw: StreamTransport, ctx: WolfTlsContext): AsyncStream =
  let state = WolfStreamState(conn: newWolfTlsConnection(raw, ctx))
  let baseReader = newAsyncStreamReader(raw)
  let baseWriter = newAsyncStreamWriter(raw)
  let reader = AsyncStreamReader()
  let writer = AsyncStreamWriter()

  reader.init(baseReader, wolfReaderLoop, WolfReaderBufferSize, state)
  writer.init(baseWriter, wolfWriterLoop, 0, state)

  AsyncStream(reader: reader, writer: writer)
