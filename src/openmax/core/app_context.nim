import ../config/types
import ../db/store

type
  AppContext* = ref object
    config*: AppConfig
    db*: AppDatabase

proc newAppContext*(config: AppConfig, db: AppDatabase): AppContext =
  AppContext(config: config, db: db)
