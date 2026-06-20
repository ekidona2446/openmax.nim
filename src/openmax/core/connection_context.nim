import ./protocols
import ./app_context

type
  ConnectionContext* = ref object
    app*: AppContext
    protocol*: ProtocolKind
    peer*: string
    deviceType*: string
    deviceName*: string
    appVersion*: string

proc newConnectionContext*(app: AppContext,
                           protocol: ProtocolKind,
                           peer: string): ConnectionContext =
  ConnectionContext(
    app: app,
    protocol: protocol,
    peer: peer,
    deviceType: "",
    deviceName: "",
    appVersion: ""
  )
