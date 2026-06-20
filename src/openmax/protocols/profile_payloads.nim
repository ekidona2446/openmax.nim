import std/times
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
      location: "RU",
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
