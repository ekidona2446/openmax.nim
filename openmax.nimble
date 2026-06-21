version       = "0.0.1"
author        = "nierneon"
description   = "Nim rewrite of OpenMAX server"
license       = "AGPL v3"
srcDir        = "src"
bin           = @["openmax"]

requires "nim >= 2.2.10", "chronos", "toml_serialization", "msgpack4nim", "websock"
