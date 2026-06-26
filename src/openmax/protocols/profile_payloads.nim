import std/[times, json, strutils]
import ../db/sqlite_abi
import ./auth_utils

type
  ProfileName* = object
    name*: string
    firstName*: string
    lastName*: string
    `type`*: string

  OnemeContactProfile* = object
    id*: int64
    updateTime*: int64
    phone*: int64
    names*: seq[ProfileName]
    options*: seq[string]
    accountStatus*: int
    location*: string
    registrationTime*: int64
    description*: string
    link*: string

  OnemeProfilePayload* = object
    contact*: OnemeContactProfile
    profileOptions*: seq[int]

  TamtamSimpleName* = object
    name*: string
    `type`*: string

  TamtamContactProfile* = object
    id*: int64
    updateTime*: int64
    phone*: int64
    names*: seq[TamtamSimpleName]
    options*: seq[string]
    description*: string
    link*: string

proc currentRegistrationTime(): int64 =
  (epochTime() * 1000.0).int64

proc buildOnemeProfile*(user: DbRow): OnemeProfilePayload =
  let firstName = rowString(user, "firstname")
  let lastName = rowString(user, "lastname")
  let displayName = if lastName.len > 0: firstName & " " & lastName else: firstName

  OnemeProfilePayload(
    contact: OnemeContactProfile(
      id: rowInt64(user, "id"),
      updateTime: rowInt64(user, "updatetime"),
      phone: rowInt64(user, "phone"),
      names: @[ProfileName(
        name: displayName,
        firstName: firstName,
        lastName: lastName,
        `type`: "ONEME"
      )],
      options: rowStringSeq(user, "options"),
      accountStatus: rowInt64(user, "accountstatus").int,
      location: countryForUserRow(user),
      registrationTime: currentRegistrationTime(),
      description: rowString(user, "description"),
      link: ""
    ),
    profileOptions: @[]
  )

proc buildTamtamProfile*(user: DbRow): TamtamContactProfile =
  let firstName = rowString(user, "firstname")
  let lastName = rowString(user, "lastname")
  let displayName = if lastName.len > 0: firstName & " " & lastName else: firstName

  TamtamContactProfile(
    id: rowInt64(user, "id"),
    updateTime: rowInt64(user, "updatetime"),
    phone: rowInt64(user, "phone"),
    names: @[TamtamSimpleName(name: displayName, `type`: "TT")],
    options: rowStringSeq(user, "options"),
    description: rowString(user, "description"),
    link: ""
  )

# ---------------------------------------------------------------------------
# JSON profile builder mirroring Python tools.generate_profile.
# Used by handlers that need the richer contact shape (custom names, blocked
# status, avatar urls, username link, profileOptions) which the typed
# OnemeProfilePayload above does not express.
# ---------------------------------------------------------------------------

proc optionsJson(row: DbRow, key: string): JsonNode =
  result = newJArray()
  let raw = rowString(row, key).strip()
  if raw.len == 0:
    return
  try:
    let parsed = parseJson(raw)
    if parsed.kind == JArray:
      return parsed
  except CatchableError:
    discard
  for item in rowStringSeq(row, key):
    result.add %item

proc generateOnemeProfileJson*(user: DbRow,
                               avatarBaseUrl = "";
                               includeProfileOptions = false;
                               customFirstName = "";
                               customLastName = "";
                               blocked = false): JsonNode =
  ## Port of Python tools.generate_profile (oneme variant).
  let firstName = rowString(user, "firstname")
  let lastName = rowString(user, "lastname")
  let username = rowString(user, "username")
  let description = rowString(user, "description")
  let avatarId = rowString(user, "avatar_id")

  var names = newJArray()
  names.add %*{
    "name": firstName,
    "firstName": firstName,
    "lastName": lastName,
    "type": "ONEME"
  }

  var contact = %*{
    "id": rowInt64(user, "id"),
    "updateTime": rowInt64(user, "updatetime"),
    "phone": rowInt64(user, "phone"),
    "names": names,
    "options": optionsJson(user, "options"),
    "accountStatus": rowInt64(user, "accountstatus").int,
    "location": countryForUserRow(user),
    "registrationTime": (epochTime() * 1000.0).int64
  }

  if avatarId.len > 0 and avatarBaseUrl.len > 0:
    let avatarUrl = avatarBaseUrl & avatarId
    contact["photoId"] = %rowInt64(user, "avatar_id")
    contact["baseUrl"] = %avatarUrl
    contact["baseRawUrl"] = %avatarUrl

  if description.len > 0:
    contact["description"] = %description

  if username.len > 0:
    contact["link"] = %("https://max.ru/" & username)

  if customFirstName.len > 0:
    contact["names"].add %*{
      "name": customFirstName,
      "firstName": customFirstName,
      "lastName": customLastName,
      "type": "CUSTOM"
    }

  if blocked:
    contact["status"] = %"BLOCKED"

  if includeProfileOptions:
    result = %*{"contact": contact, "profileOptions": optionsJson(user, "profileoptions")}
  else:
    result = contact
