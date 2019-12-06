{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs               #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module ExampleApp where

import           ClassyPrelude.Yesod
import           Data.Coerce          (coerce)
import qualified Data.Vector          as Vec
import           Database.Persist.Sql
import           Yesod.Auth
import           Yesod.Auth.Simple
import           Yesod.Core.Types     (Logger)

data App = App
  { appLogger   :: Logger
  , appConnPool :: ConnectionPool
  }

mkYesod "App" [parseRoutes|
/auth AuthR Auth getAuth
/ HomeR GET
|]

getHomeR :: Handler ()
getHomeR = pure ()

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
User
  email Email
  password Password
  UniqueUser email
  deriving Show
|]

instance Yesod App

instance YesodPersist App where
  type YesodPersistBackend App = SqlBackend

  runDB :: SqlPersistT Handler a -> Handler a
  runDB db = getsYesod appConnPool >>= runSqlPool db

instance YesodAuth App where
  type AuthId App = Key User
  loginDest _ = HomeR
  logoutDest _ = HomeR
  authPlugins _ = [ authSimple ]
  getAuthId = return . fromPathPiece . credsIdent
  maybeAuthId = defaultMaybeAuthId

instance YesodAuthSimple App where
  type AuthSimpleId App = Key User

  getUserId email' = liftHandler . runDB $ do
    let email = Email . toLower . coerce $ email'
    res <- getBy $ UniqueUser email
    return $ case res of
      Just (Entity uid _) -> Just uid
      _                   -> Nothing

  getUserPassword = do
    let mkPass = EncryptedPass . encodeUtf8 . coerce . userPassword
    liftHandler . runDB . fmap mkPass . get404

  afterPasswordRoute = error "forced afterPasswordRoute"
  getUserModified = error "forced getUserModified"
  updateUserPassword = error "forced updateUserPassword"

  onRegisterSuccess = sendResponseStatus ok200 ()
  insertUser _email _pass = pure . Just $ (toSqlKey 1 :: Key User)
  passwordCheck = Zxcvbn Safe (Vec.fromList ["yesod"])

instance YesodAuthPersist App

instance RenderMessage App FormMessage where
  renderMessage _ _ = defaultFormMessage
