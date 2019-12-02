{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs               #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Yesod.Auth.SimpleSpec (main) where

import           Control.Monad                        (when)
import           Control.Monad.Logger                 (runLoggingT)
import           Data.Coerce                          (coerce)
import           Data.Text                            (toLower)
import           Data.Text.Encoding
import qualified Data.Vector                          as Vec
import           Database.Persist.Sql                 (ConnectionPool,
                                                       SqlBackend, SqlPersistM,
                                                       SqlPersistT,
                                                       runMigration,
                                                       runSqlPersistMPool,
                                                       runSqlPool, toSqlKey)
import           Database.Persist.Sqlite              (createSqlitePool)
import           Network.HTTP.Types.Status            (ok200)
import           System.Directory
import           System.Log.FastLogger                (newStdoutLoggerSet)
import           Test.Hspec
import           Yesod                                hiding (get)
import           Yesod.Auth
import           Yesod.Auth.Simple
import           Yesod.Core.Types                     (Logger)
import           Yesod.Core.Unsafe                    (fakeHandlerGetLogger)
import           Yesod.Default.Config2                (makeYesodLogger)
import           Yesod.Test

--------------------------------------------------------------------------------
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
  commonDomainWords = Vec.fromList ["yesod"]

instance YesodAuthPersist App

instance RenderMessage App FormMessage where
  renderMessage _ _ = defaultFormMessage

--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
main :: IO ()
main = hspec . withApp $ do

  describe "registration" $ do

    it "renders the registration form" $ do
      get $ AuthR registerR
      statusIs 200
      htmlCount "input[type=email]" 1
      htmlCount "button[type=submit]" 1

    describe "with a valid email address" $

      it "renders the confirmation email sent page" $ do
        let email = "user@example.com"
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" email
        _ <- followRedirect
        statusIs 200
        bodyContains "Email sent"

    describe "with an invalid email address" $

      it "returns the user to the registration form with an error" $ do
        let email = "not_an_email"
        ur <- runHandler getUrlRender
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" email
        r <- followRedirect
        assertEq "path is registration form" (Right (ur (AuthR registerR))) r

  describe "confirmation" $ do

    describe "with a weak password" $

      it "returns the user to the confirmation form with an error" $ do
        let email = "user@example.com"
        ur <- runHandler getUrlRender
        t <- liftIO $ encryptRegisterToken (Email email)
        get $ AuthR $ confirmR t
        request $ do
          setMethod "POST"
          setUrl $ AuthR $ confirmR t
          -- NB: The following password would be fine without the
          -- commonDomainWords definition
          byLabelExact "Password" "hello yesod 123"
        r <- followRedirect
        assertEq "path is confirmation form" (Right (ur (AuthR (confirmR t)))) r

    describe "with an adequately strong password" $ do

      it "inserts a new user" $ do
        let email = "user@example.com"
        ur <- runHandler getUrlRender
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" email
        token <- liftIO $ encryptRegisterToken (Email email)
        get $ AuthR $ confirmR token
        request $ do
          setMethod "POST"
          setUrl $ AuthR $ confirmR token
          byLabelExact "Password" "really difficult yesod password here"
        r <- followRedirect
        assertNotEq "path is not confirmation form" (Right (ur (AuthR (confirmR token)))) r

    describe "with an invalid token" $

      it "renders the invalid token page" $ do
        let token = "not_a_valid_token"
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" "user@example.com"
        get $ AuthR $ confirmR token
        statusIs 400

    describe "with an email that is not unique" $

      it "automatically authenticates the existing user" $ do
        encrypted <- liftIO $ encryptPassIO' $ Pass "strongpass"
        let userEmail = Email  "user@example.com"
            userPassword = Password . decodeUtf8 . getEncryptedPass $ encrypted
        runDB' . insert_ $ User{..}

        token <- liftIO $ encryptRegisterToken userEmail
        get $ AuthR $ confirmR token
        statusIs 303
        r <- followRedirect
        ur <- runHandler getUrlRender
        assertEq "redirection successful" r (Right $ ur HomeR)
