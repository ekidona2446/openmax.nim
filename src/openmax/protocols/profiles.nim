import ../core/protocols

type
  ProtocolProfile* = object
    kind*: ProtocolKind
    name*: string
    session_namespace*: string

const
  OnemeProfile* = ProtocolProfile(
    kind: pkOneme,
    name: "MAX / Oneme",
    session_namespace: "oneme"
  )

  TamtamProfile* = ProtocolProfile(
    kind: pkTamtam,
    name: "TamTam",
    session_namespace: "tamtam"
  )
