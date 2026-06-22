type
  ServerConfig* = object
    host*: string
    dualstack_mode*: string
    log_level*: string

  TlsConfig* = object
    enabled*: bool
    cert_file*: string
    key_file*: string
    min_version*: string
    max_version*: string

  DatabaseConfig* = object
    kind*: string
    mysql_host*: string
    mysql_port*: int
    mysql_user*: string
    mysql_password*: string
    mysql_database*: string
    sqlite_file*: string

  ServiceUrlsConfig* = object
    avatar_base_url*: string
    origins*: seq[string]

  ProtocolsConfig* = object
    oneme_tcp_enabled*: bool
    oneme_tcp_port*: int
    oneme_ws_enabled*: bool
    oneme_ws_port*: int
    tamtam_tcp_enabled*: bool
    tamtam_tcp_port*: int
    tamtam_ws_enabled*: bool
    tamtam_ws_port*: int

  IntegrationsConfig* = object
    telegram_enabled*: bool
    telegram_token*: string
    telegram_whitelist_enabled*: bool
    telegram_whitelist_ids*: seq[string]
    sms_gateway_url*: string
    push_firebase_credentials_path*: string
    geoip_db_path*: string

  AppConfig* = object
    server*: ServerConfig
    tls*: TlsConfig
    database*: DatabaseConfig
    service_urls*: ServiceUrlsConfig
    protocols*: ProtocolsConfig
    integrations*: IntegrationsConfig
