import chronos
import ../core/protocols
import ../core/connection_context
import ../proto/mobile_frame
import ./oneme/tcp_handler as oneme_tcp
import ./tamtam/tcp_handler as tamtam_tcp

proc dispatchTcpFrame*(ctx: ConnectionContext,
                       transp: MobileTransport,
                       frame: MobileFrame): Future[void] {.async.} =
  case ctx.protocol
  of pkOneme:
    await oneme_tcp.handleTcpFrame(ctx, transp, frame)
  of pkTamtam:
    await tamtam_tcp.handleTcpFrame(ctx, transp, frame)
