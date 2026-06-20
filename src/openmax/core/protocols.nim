import std/strformat
import ../config/types

type
  ProtocolKind* = enum
    pkOneme
    pkTamtam

  TransportKind* = enum
    tkTcp
    tkWebSocket

  ListenerSpec* = object
    protocol*: ProtocolKind
    transport*: TransportKind
    host*: string
    port*: int
    tls_enabled*: bool
    dualstack_mode*: string

proc `$`*(kind: ProtocolKind): string =
  case kind
  of pkOneme: "oneme"
  of pkTamtam: "tamtam"

proc `$`*(kind: TransportKind): string =
  case kind
  of tkTcp: "tcp"
  of tkWebSocket: "ws"

proc describe*(spec: ListenerSpec): string =
  let tlsSuffix = if spec.tls_enabled and spec.transport == tkTcp: " tls" else: ""
  &"{spec.protocol}/{spec.transport} {spec.host}:{spec.port}{tlsSuffix}"

proc buildListenerSpecs*(config: AppConfig): seq[ListenerSpec] =
  result = @[]

  if config.protocols.oneme_tcp_enabled:
    result.add ListenerSpec(
      protocol: pkOneme,
      transport: tkTcp,
      host: config.server.host,
      port: config.protocols.oneme_tcp_port,
      tls_enabled: config.tls.enabled,
      dualstack_mode: config.server.dualstack_mode
    )

  if config.protocols.oneme_ws_enabled:
    result.add ListenerSpec(
      protocol: pkOneme,
      transport: tkWebSocket,
      host: config.server.host,
      port: config.protocols.oneme_ws_port,
      tls_enabled: config.tls.enabled,
      dualstack_mode: config.server.dualstack_mode
    )

  if config.protocols.tamtam_tcp_enabled:
    result.add ListenerSpec(
      protocol: pkTamtam,
      transport: tkTcp,
      host: config.server.host,
      port: config.protocols.tamtam_tcp_port,
      tls_enabled: config.tls.enabled,
      dualstack_mode: config.server.dualstack_mode
    )

  if config.protocols.tamtam_ws_enabled:
    result.add ListenerSpec(
      protocol: pkTamtam,
      transport: tkWebSocket,
      host: config.server.host,
      port: config.protocols.tamtam_ws_port,
      tls_enabled: config.tls.enabled,
      dualstack_mode: config.server.dualstack_mode
    )
