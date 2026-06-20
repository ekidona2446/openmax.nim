import std/strutils

type
  Sha256Error* = object of CatchableError

const
  CryptoDynLib = "libcrypto.so.3"
  Sha256DigestSize* = 32

proc sha256Raw(data: cstring, len: culong,
               md: ptr cuchar): ptr cuchar {.importc: "SHA256", dynlib: CryptoDynLib.}

proc toHexLower(data: openArray[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add toHex(int(b), 2).toLowerAscii()

proc sha256Hex*(data: string): string =
  var digest: array[Sha256DigestSize, byte]
  let res = sha256Raw(data.cstring, culong(data.len), cast[ptr cuchar](addr digest[0]))
  if res.isNil:
    raise newException(Sha256Error, "SHA256() returned nil")
  toHexLower(digest)
