## Small self-contained SHA-256 implementation.
##
## We keep this in-tree instead of depending on libcrypto because token/code
## hashing is part of the OpenMAX database contract and should work in minimal
## deployments as well as in the sandbox.

import std/strutils

type
  Sha256Error* = object of CatchableError

const
  Sha256DigestSize* = 32
  K: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

func rotr(x: uint32, n: int): uint32 {.inline.} =
  (x shr n) or (x shl (32 - n))

func ch(x, y, z: uint32): uint32 {.inline.} =
  (x and y) xor ((not x) and z)

func maj(x, y, z: uint32): uint32 {.inline.} =
  (x and y) xor (x and z) xor (y and z)

func bigSigma0(x: uint32): uint32 {.inline.} =
  rotr(x, 2) xor rotr(x, 13) xor rotr(x, 22)

func bigSigma1(x: uint32): uint32 {.inline.} =
  rotr(x, 6) xor rotr(x, 11) xor rotr(x, 25)

func smallSigma0(x: uint32): uint32 {.inline.} =
  rotr(x, 7) xor rotr(x, 18) xor (x shr 3)

func smallSigma1(x: uint32): uint32 {.inline.} =
  rotr(x, 17) xor rotr(x, 19) xor (x shr 10)

func readU32Be(data: openArray[byte], offset: int): uint32 {.inline.} =
  (uint32(data[offset]) shl 24) or
    (uint32(data[offset + 1]) shl 16) or
    (uint32(data[offset + 2]) shl 8) or
    uint32(data[offset + 3])

proc writeU32Be(value: uint32, outp: var openArray[byte], offset: int) =
  outp[offset] = byte((value shr 24) and 0xff'u32)
  outp[offset + 1] = byte((value shr 16) and 0xff'u32)
  outp[offset + 2] = byte((value shr 8) and 0xff'u32)
  outp[offset + 3] = byte(value and 0xff'u32)

proc toHexLower(data: openArray[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add toHex(int(b), 2).toLowerAscii()

proc sha256Digest*(data: openArray[byte]): array[Sha256DigestSize, byte] =
  var h: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  let bitLen = uint64(data.len) * 8'u64
  var paddedLen = data.len + 1 + 8
  while (paddedLen mod 64) != 0:
    inc paddedLen

  var msg = newSeq[byte](paddedLen)
  for i, b in data:
    msg[i] = b
  msg[data.len] = 0x80'u8
  for i in 0 ..< 8:
    msg[paddedLen - 1 - i] = byte((bitLen shr (8 * i)) and 0xff'u64)

  var w: array[64, uint32]
  var offset = 0
  while offset < msg.len:
    for i in 0 ..< 16:
      w[i] = readU32Be(msg, offset + i * 4)
    for i in 16 ..< 64:
      w[i] = smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16]

    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    var e = h[4]
    var f = h[5]
    var g = h[6]
    var hh = h[7]

    for i in 0 ..< 64:
      let t1 = hh + bigSigma1(e) + ch(e, f, g) + K[i] + w[i]
      let t2 = bigSigma0(a) + maj(a, b, c)
      hh = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2

    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh

    offset += 64

  for i in 0 ..< 8:
    writeU32Be(h[i], result, i * 4)

proc sha256Hex*(data: string): string =
  var bytes = newSeq[byte](data.len)
  for i, ch in data:
    bytes[i] = byte(ord(ch) and 0xff)
  toHexLower(sha256Digest(bytes))
