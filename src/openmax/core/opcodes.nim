const
  ProtoVer* = 10'u8

  CmdOk* = 1'u8
  CmdNof* = 2'u8
  CmdErr* = 3'u8

  PingOpcode* = 1'u16
  LogOpcode* = 5'u16
  SessionInitOpcode* = 6'u16
  ProfileOpcode* = 16'u16
  AuthRequestOpcode* = 17'u16
  AuthOpcode* = 18'u16
  LoginOpcode* = 19'u16
  LogoutOpcode* = 20'u16
  AuthConfirmOpcode* = 23'u16
