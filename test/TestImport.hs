{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module TestImport
  ( module TestImport
  , module X
  ) where

import ClassyPrelude as X hiding (Handler, delete, deleteBy)
import Control.Monad.Logger (runLoggingT)
import Database.Persist as X hiding (get)
import Database.Persist.Sql
       (SqlPersistM, runMigration, runSqlPersistMPool, runSqlPool)
import Database.Persist.Sqlite (createSqlitePool)
import ExampleApp as X
import System.Directory
import System.Log.FastLogger (newStdoutLoggerSet)
import Test.Hspec as X
import Yesod hiding (get)
import Yesod.Auth.Simple as X
import Yesod.Core as X
import Yesod.Core.Unsafe (fakeHandlerGetLogger)
import Yesod.Default.Config2 (makeYesodLogger)
import Yesod.Test as X

withApp :: SpecWith (TestApp App) -> Spec
withApp = before $ do
  appLogger <- newStdoutLoggerSet 1 >>= makeYesodLogger

  let mkFoundation appConnPool = App {..}
      tempFoundation = mkFoundation $ error "connPool forced in tempFoundation"
      logFunc = messageLoggerSource tempFoundation appLogger

  removeIfExists "auth.sqlite3"
  pool <- flip runLoggingT logFunc $ createSqlitePool "auth.sqlite3" 10
  runLoggingT (runSqlPool (runMigration migrateAll) pool) logFunc
  pure (mkFoundation pool, defaultMiddlewaresNoLogging)

runHandler :: Handler a -> YesodExample App a
runHandler handler = do
  app <- getTestYesod
  fakeHandlerGetLogger appLogger app handler

runDB' :: SqlPersistM a -> YesodExample App a
runDB' query = do
  app <- getTestYesod
  liftIO $ runDBWithApp app query

runDBWithApp :: App -> SqlPersistM a -> IO a
runDBWithApp app query = runSqlPersistMPool query (appConnPool app)

removeIfExists :: FilePath -> IO ()
removeIfExists f = do
  fileExists <- doesFileExist f
  when fileExists (removeFile f)

-- | Follow a redirect and discard the result
followRedirect_ :: Yesod a => YesodExample a ()
followRedirect_ = void followRedirect
