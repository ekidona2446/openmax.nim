import std/[os, strutils]
import toml_serialization
import ./types

proc resolveConfigPath*(cliArgs: seq[string]): string =
  if cliArgs.len > 0 and cliArgs[0].strip().len > 0:
    return cliArgs[0]

  let envPath = getEnv("OPENMAX_CONFIG")
  if envPath.strip().len > 0:
    return envPath

  "config.toml"

proc loadConfig*(path: string): AppConfig =
  if not fileExists(path):
    raise newException(IOError, "Config file not found: " & path)

  Toml.loadFile(path, AppConfig)
