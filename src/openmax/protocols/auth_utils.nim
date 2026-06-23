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

proc countryFromLocale*(locale: string, fallback = "RU"): string =
  ## Extract `RU` from values like `ru_RU`, `ru-RU`, `en-US`.
  let value = locale.strip()
  if value.len >= 5:
    let sepPos = max(value.rfind('_'), value.rfind('-'))
    if sepPos >= 0 and sepPos + 2 < value.len:
      let code = value[sepPos + 1 .. sepPos + 2].toUpperAscii()
      if code.len == 2 and code[0] in {'A'..'Z'} and code[1] in {'A'..'Z'}:
        return code
  fallback

proc countryFromPhone*(phone: string, fallback = "RU"): string =
  ## Small E.164 prefix map used when GeoIP is unavailable.
  ## The Python server also stored a string location in tokens; deriving it from
  ## the phone is better than returning RU for everyone.
  let p = normalizePhone(phone)
  if p.len == 0:
    return fallback

  const prefixes = [
    ("375", "BY"), ("380", "UA"), ("374", "AM"), ("995", "GE"),
    ("994", "AZ"), ("996", "KG"), ("998", "UZ"), ("992", "TJ"),
    ("993", "TM"), ("373", "MD"), ("372", "EE"), ("371", "LV"),
    ("370", "LT"), ("48", "PL"), ("49", "DE"), ("33", "FR"),
    ("34", "ES"), ("39", "IT"), ("44", "GB"), ("90", "TR"),
    ("86", "CN"), ("81", "JP"), ("82", "KR"), ("91", "IN"),
    ("55", "BR"), ("52", "MX"), ("1", "US"), ("7", "RU")
  ]

  for (prefix, country) in prefixes:
    if p.startsWith(prefix):
      return country
  fallback

proc countryForUserRow*(row: DbRow, fallback = "RU"): string =
  countryFromPhone(rowString(row, "phone"), fallback)

proc countryFromUserAgent*(locale, deviceLocale, fallback: string): string =
  let fromDevice = countryFromLocale(deviceLocale, "")
  if fromDevice.len == 2: return fromDevice
  let fromLocale = countryFromLocale(locale, "")
  if fromLocale.len == 2: return fromLocale
  fallback
