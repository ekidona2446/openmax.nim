import ../proto/mobile_rpc

proc invalidPayloadError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Ошибка валидации",
    error: "proto.payload",
    message: "Invalid payload",
    title: "Ошибка валидации"
  )

proc notImplementedError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Не реализовано",
    error: "proto.opcode",
    message: "Not implemented",
    title: "Не реализовано"
  )

proc invalidCompressionError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Сжатые payload пока не поддерживаются",
    error: "proto.compression",
    message: "Compressed payload is not supported yet",
    title: "Сжатие пока не поддерживается"
  )

proc codeExpiredError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Этот код устарел, запросите новый",
    error: "error.code.expired",
    message: "Code expired",
    title: "Этот код устарел, запросите новый"
  )

proc invalidCodeError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Неверный код",
    error: "error.code.wrong",
    message: "Invalid code",
    title: "Неверный код"
  )

proc invalidTokenError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Ошибка входа. Пожалуйста, авторизируйтесь снова",
    error: "login.token",
    message: "Invalid token",
    title: "Ошибка входа. Пожалуйста, авторизируйтесь снова"
  )

proc userNotFoundError*(): ErrorPayload =
  ErrorPayload(
    localizedMessage: "Не нашли этот номер, проверьте цифры",
    error: "error.phone.wrong",
    message: "User not found",
    title: "Не нашли этот номер, проверьте цифры"
  )
