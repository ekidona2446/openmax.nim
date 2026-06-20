import std/strformat

# when defined(windows)
#	const liblz4* = "liblz4.dll"
# elif defined(macosx)
#	const liblz4* = "liblz4.dylib"
# else:
#	const liblz4* = "liblz4.so.1"

type
  Lz4Error* = object of CatchableError

const
  DefaultLz4CompressionFlag* = 2'u8
  DefaultLz4CompressionLevel* = 9

proc lz4CompressBound(inputSize: cint): cint {.
  importc: "LZ4_compressBound",
  dynlib: "liblz4.so.1"
.}
proc lz4CompressHC(src: ptr char, dst: ptr char,
                   srcSize: cint, dstCapacity: cint,
                   compressionLevel: cint): cint {.
  importc: "LZ4_compress_HC",
  dynlib: "liblz4.so.1"
.}
proc lz4DecompressSafe(src: ptr char, dst: ptr char,
                       compressedSize: cint,
                       dstCapacity: cint): cint {.
  importc: "LZ4_decompress_safe",
  dynlib: "liblz4.so.1"
.}

proc compressBlock*(input: openArray[byte],
                    compressionLevel = DefaultLz4CompressionLevel): seq[byte] =
  if input.len == 0:
    return @[]

  let bound = int(lz4CompressBound(cint(input.len)))
  if bound <= 0:
    raise newException(Lz4Error, "LZ4_compressBound returned non-positive size")

  result = newSeq[byte](bound)
  let written = lz4CompressHC(
    cast[ptr char](unsafeAddr input[0]),
    cast[ptr char](addr result[0]),
    cint(input.len),
    cint(result.len),
    cint(compressionLevel)
  )

  if written <= 0:
    raise newException(Lz4Error, "LZ4_compress_HC failed")

  result.setLen(int(written))

proc decompressBlock*(input: openArray[byte], maxOutputSize: int): seq[byte] =
  if input.len == 0:
    return @[]

  if maxOutputSize <= 0:
    raise newException(Lz4Error, "maxOutputSize must be positive")

  result = newSeq[byte](maxOutputSize)
  let written = lz4DecompressSafe(
    cast[ptr char](unsafeAddr input[0]),
    cast[ptr char](addr result[0]),
    cint(input.len),
    cint(result.len)
  )

  if written < 0:
    raise newException(Lz4Error, &"LZ4_decompress_safe failed with code {written}")

  result.setLen(int(written))

proc maybeCompressBlock*(input: openArray[byte],
                         preferredFlag = DefaultLz4CompressionFlag,
                         compressionLevel = DefaultLz4CompressionLevel): tuple[
                           compressionFlag: uint8,
                           payload: seq[byte]
                         ] =
  if input.len == 0:
    return (0'u8, @[])

  let compressed = compressBlock(input, compressionLevel)
  if compressed.len < input.len:
    (preferredFlag, compressed)
  else:
    (0'u8, @input)
