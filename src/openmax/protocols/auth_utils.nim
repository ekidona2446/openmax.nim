import std/[random, times, tables, strutils]
import ../db/[store, sqlite_abi]

const
  AlphaNumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

proc initAuthRandomizer() =
  randomize(int(epochTime()))

initAuthRandomizer()

proc generateRandomString*(length: int): string =
  result = newStringOfCap(length)
  for _ in 0 ..< length:
    result.add AlphaNumChars[rand(AlphaNumChars.high)]

proc generateCode*(length = 6): string =
  result = $rand(999_999)
  while result.len < length:
    result = "0" & result
  if result.len > length:
    result = result[0 ..< length]

proc normalizePhoneNumber*(phone: string): string =
  normalizePhone(phone)

proc rowString*(row: DbRow, key: string): string =
  if row.hasKey(key): row[key] else: ""

proc rowInt64*(row: DbRow, key: string): int64 =
  let value = rowString(row, key)
  if value.len == 0:
    0'i64
  else:
    try:
      parseBiggestInt(value).int64
    except ValueError:
      0'i64

proc rowStringSeq*(row: DbRow, key: string): seq[string] =
  let value = rowString(row, key).strip()
  if value.len == 0:
    return @[]

  let trimmed = value.strip(chars = {'[', ']', ' '})
  if trimmed.len == 0:
    return @[]

  for item in trimmed.split(','):
    let cleaned = item.strip().strip(chars = {'"', '\''})
    if cleaned.len > 0:
      result.add cleaned
