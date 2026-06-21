{.passC: "-Wno-incompatible-pointer-types".}

import std/os
import chronos
import openmax/app
import openmax/config/loader

when isMainModule:
  let configPath = resolveConfigPath(commandLineParams())
  waitFor run(configPath)
