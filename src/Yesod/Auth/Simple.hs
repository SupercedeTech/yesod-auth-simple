{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE Rank2Types        #-}
{-# LANGUAGE TypeFamilies      #-}

module Yesod.Auth.Simple (
  YesodAuthSimple(..),
  authSimple,
  loginR,
  registerR,
  setPasswordR,
  resetPasswordR,
  resetPasswordEmailSentR,
  setPasswordTokenR,
  confirmR,
  userExistsR,
  registerSuccessR,
  confirmationEmailSentR
) where

import           Crypto.Hash.MD5            (hash)
import           Crypto.PasswordStore       (makePassword, verifyPassword)
import           Data.Aeson
import           Data.ByteString            (ByteString)
import           Data.ByteString.Base16     as B16
import qualified Data.ByteString.Base64     as B64
import qualified Data.ByteString.Base64.URL as B64Url
import           Data.Maybe                 (fromJust)
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import           Data.Text.Encoding         (decodeUtf8With, encodeUtf8, decodeUtf8)
import           Data.Text.Encoding.Error   (lenientDecode)
import           Data.Time                  (UTCTime, addUTCTime, diffUTCTime,
                                             getCurrentTime)
import           GHC.Generics
import           Network.HTTP.Types         (status400)
import           Text.Email.Validate        (canonicalizeEmail)
import qualified Web.ClientSession          as CS
import           Yesod.Auth
import           Yesod.Core
import           Yesod.Form                 (ireq, runInputPost, textField)

data Passwords = Passwords
  { passwordsOriginal :: Text
  , passwordsConfirm  :: Text
  } deriving (Show, Generic)

instance FromJSON Passwords

loginR :: AuthRoute
loginR = PluginR "simple" ["login"]

registerR :: AuthRoute
registerR = PluginR "simple" ["register"]

confirmationEmailSentR :: AuthRoute
confirmationEmailSentR = PluginR "simple" ["confirmation-email-sent"]

registerSuccessR :: AuthRoute
registerSuccessR = PluginR "simple" ["register-success"]

userExistsR :: AuthRoute
userExistsR = PluginR "simple" ["user-exists"]

confirmR :: Text -> AuthRoute
confirmR token = PluginR "simple" ["confirm", token]

setPasswordR :: AuthRoute
setPasswordR = PluginR "simple" ["set-password"]

setPasswordTokenR :: Text -> AuthRoute
setPasswordTokenR token = PluginR "simple" ["set-password", token]

resetPasswordR :: AuthRoute
resetPasswordR = PluginR "simple" ["reset-password"]

resetPasswordEmailSentR :: AuthRoute
resetPasswordEmailSentR = PluginR "simple" ["reset-password-email-sent"]

type Email = Text
type VerUrl = Text
type SaltedPass = Text

class (YesodAuth a, PathPiece (AuthSimpleId a)) => YesodAuthSimple a where
    type AuthSimpleId a

    sendVerifyEmail :: Email -> VerUrl -> AuthHandler a ()

    sendResetPasswordEmail :: Email -> VerUrl -> AuthHandler a ()

    getUserId :: Email -> AuthHandler a (Maybe (AuthSimpleId a))

    getUserPassword :: AuthSimpleId a -> AuthHandler a SaltedPass

    getUserModified :: AuthSimpleId a -> AuthHandler a UTCTime

    insertUser :: Email -> Text -> AuthHandler a (Maybe (AuthSimpleId a))

    updateUserPassword :: AuthSimpleId a -> Text -> AuthHandler a ()

    afterPasswordRoute :: a -> Route a

    loginTemplate :: Maybe Text -> WidgetFor a ()

    registerTemplate :: Maybe Text -> WidgetFor a ()

    resetPasswordTemplate :: Maybe Text -> WidgetFor a ()

    confirmTemplate :: Route a -> Email -> Maybe Text -> WidgetFor a ()

    confirmationEmailSentTemplate :: WidgetFor a ()

    resetPasswordEmailSentTemplate :: WidgetFor a ()

    registerSuccessTemplate :: WidgetFor a ()

    userExistsTemplate :: WidgetFor a ()

    invalidTokenTemplate :: Text -> WidgetFor a ()

    setPasswordTemplate :: Route a -> Maybe Text -> WidgetFor a ()

    onPasswordUpdated :: AuthHandler a ()
    onPasswordUpdated = setMessage "Password has been updated"

authSimple :: YesodAuthSimple m => AuthPlugin m
authSimple = AuthPlugin "simple" dispatch loginHandlerRedirect

loginHandlerRedirect :: (Route Auth -> Route master) -> WidgetFor master ()
loginHandlerRedirect tm = redirectTemplate $ tm loginR

dispatch :: YesodAuthSimple a => Text -> [Text] -> AuthHandler a TypedContent
dispatch "GET"  ["register"] = getRegisterR >>= sendResponse
dispatch "POST" ["register"] = postRegisterR >>= sendResponse
dispatch "GET"  ["confirm", token] = getConfirmR token >>= sendResponse
dispatch "POST" ["confirm", token] = postConfirmR token >>= sendResponse
dispatch "GET"  ["confirmation-email-sent"] = getConfirmationEmailSentR >>= sendResponse
dispatch "GET"  ["register-success"] = getRegisterSuccessR >>= sendResponse
dispatch "GET"  ["user-exists"] = getUserExistsR >>= sendResponse
dispatch "GET"  ["login"] = getLoginR >>= sendResponse
dispatch "POST" ["login"] = postLoginR >>= sendResponse
dispatch "GET"  ["set-password"] = getSetPasswordR >>= sendResponse
dispatch "PUT"  ["set-password"] = putSetPasswordR >>= sendResponse
dispatch "GET"  ["set-password", token] = getSetPasswordTokenR token >>= sendResponse
dispatch "POST" ["set-password", token] = postSetPasswordTokenR token >>= sendResponse
dispatch "GET"  ["reset-password"] = getResetPasswordR >>= sendResponse
dispatch "POST" ["reset-password"] = postResetPasswordR >>= sendResponse
dispatch "GET"  ["reset-password-email-sent"] = getResetPasswordEmailSentR >>= sendResponse
dispatch _ _ = notFound

getRegisterR :: YesodAuthSimple master => AuthHandler master Html
getRegisterR = do
  mErr <- getError
  muid <- maybeAuthId
  case muid of
    Nothing -> authLayout $ do
      setTitle "Register a new account"
      registerTemplate mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

getResetPasswordR :: YesodAuthSimple master => AuthHandler master Html
getResetPasswordR = do
  mErr <- getError
  authLayout $ do
    setTitle "Reset password"
    resetPasswordTemplate mErr

getLoginR :: YesodAuthSimple master => AuthHandler master Html
getLoginR = do
  mErr <- getError
  muid <- maybeAuthId
  case muid of
    Nothing -> authLayout $ do
      setTitle "Login"
      loginTemplate mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

postRegisterR :: YesodAuthSimple master => AuthHandler master Html
postRegisterR = do
  clearError
  email <- runInputPost $ ireq textField "email"
  mEmail <- validateAndNormalizeEmail email
  case mEmail of
    Just email' -> do
      token <- liftIO $ encryptRegisterToken email'
      tp <- getRouteToParent
      renderUrl <- getUrlRender
      let url = renderUrl $ tp $ confirmR token
      sendVerifyEmail email' url
      redirect $ tp confirmationEmailSentR
    Nothing -> do
      setError "Invalid email address"
      tp <- getRouteToParent
      redirect $ tp registerR

postResetPasswordR :: YesodAuthSimple master => AuthHandler master Html
postResetPasswordR = do
  clearError
  email <- runInputPost $ ireq textField "email"
  mUid <- getUserId $ normalizeEmail email
  case mUid of
    Just uid -> do
      modified <- getUserModified uid
      token <- encryptPasswordResetToken uid modified
      tp <- getRouteToParent
      renderUrl <- getUrlRender
      let url = renderUrl $ tp $ setPasswordTokenR token
      sendResetPasswordEmail email url
      redirect $ tp resetPasswordEmailSentR
    Nothing -> do
      setError "Email not found"
      tp <- getRouteToParent
      redirect $ tp resetPasswordR

getConfirmR :: YesodAuthSimple master => Text -> AuthHandler master Html
getConfirmR token = do
    res <- liftIO $ verifyRegisterToken token
    case res of
        Left msg    -> invalidTokenHandler msg
        Right email -> confirmHandlerHelper token email

invalidTokenHandler :: YesodAuthSimple master => Text -> AuthHandler master Html
invalidTokenHandler msg = authLayout $ do
  setTitle "Invalid key"
  invalidTokenTemplate msg

confirmHandlerHelper :: YesodAuthSimple master => Text -> Email -> AuthHandler master Html
confirmHandlerHelper token email = do
    tp <- getRouteToParent
    confirmHandler (tp $ confirmR token) email

confirmHandler :: YesodAuthSimple master => Route master -> Email -> AuthHandler master Html
confirmHandler registerUrl email = do
    mErr <- getError
    authLayout $ do
      setTitle "Confirm account"
      confirmTemplate registerUrl email mErr

postConfirmR :: YesodAuthSimple master => Text -> AuthHandler master Html
postConfirmR token = do
  clearError
  pass <- runInputPost $ ireq textField "password"
  res  <- liftIO $ verifyRegisterToken token
  case res of
    Left msg ->
      invalidTokenHandler msg
    Right email ->
      createUser token email pass

createUser :: YesodAuthSimple m => Text -> Email -> Text -> AuthHandler m Html
createUser token email pass = case checkPasswordStrength pass of
  Left msg -> do
    setError msg
    confirmHandlerHelper token email
  Right _ -> do
    salted <- liftIO $ saltPass pass
    mUid   <- insertUser email salted
    case mUid of
      Just uid -> do
        let creds = Creds "simple" (toPathPiece uid) []
        setCreds False creds
        tp <- getRouteToParent
        redirect $ tp registerSuccessR
      Nothing -> do
        tp <- getRouteToParent
        redirect $ tp userExistsR

getConfirmationEmailSentR :: YesodAuthSimple master => AuthHandler master Html
getConfirmationEmailSentR = authLayout $ do
  setTitle "Confirmation email sent"
  confirmationEmailSentTemplate

getResetPasswordEmailSentR :: YesodAuthSimple master => AuthHandler master Html
getResetPasswordEmailSentR = authLayout $ do
  setTitle "Reset password email sent"
  resetPasswordEmailSentTemplate

getRegisterSuccessR :: AuthHandler master Html
getRegisterSuccessR = do
  setMessage "Account created. Welcome!"
  redirect ("/" :: Text)

getUserExistsR :: YesodAuthSimple master => AuthHandler master Html
getUserExistsR = authLayout $ do
  setTitle "User already exists"
  userExistsTemplate

checkPasswordStrength :: Text -> Either Text ()
checkPasswordStrength x
  | T.length x >= 6 = Right ()
  | otherwise = Left "Password must be at least six characters"

normalizeEmail :: Text -> Text
normalizeEmail = T.toLower

validateAndNormalizeEmail :: Text -> AuthHandler master (Maybe Text)
validateAndNormalizeEmail email = case canonicalizeEmail $ encodeUtf8 email of
  Just bytes ->
      return $ Just $ normalizeEmail $ decodeUtf8With lenientDecode bytes
  Nothing -> return Nothing

getError :: AuthHandler master (Maybe Text)
getError = do
  mErr <- lookupSession "error"
  clearError
  return mErr

setError :: Text -> AuthHandler master ()
setError = setSession "error"

clearError :: AuthHandler master ()
clearError = deleteSession "error"

postLoginR :: YesodAuthSimple master => AuthHandler master TypedContent
postLoginR = do
  clearError
  (email, pass) <- runInputPost $ (,)
    <$> ireq textField "email"
    <*> ireq textField "password"
  mUid <- getUserId email
  case mUid of
    Just uid -> do
      realPass <- getUserPassword uid
      if isValidPass pass realPass
      then setCredsRedirect $ Creds "simple" (toPathPiece uid) []
      else wrongEmailOrPasswordRedirect
    _ -> wrongEmailOrPasswordRedirect

wrongEmailOrPasswordRedirect :: AuthHandler master TypedContent
wrongEmailOrPasswordRedirect = do
  setError "Wrong email or password"
  tp <- getRouteToParent
  redirect $ tp loginR

toSimpleAuthId :: forall c a. (PathPiece c, PathPiece a) => a -> c
toSimpleAuthId = fromJust . fromPathPiece . toPathPiece

getSetPasswordR :: YesodAuthSimple master => AuthHandler master Html
getSetPasswordR = do
  mUid <- maybeAuthId
  tp <- getRouteToParent
  case mUid of
    Just _ -> do
      mErr <- getError
      authLayout $ do
        setTitle "Set password"
        setPasswordTemplate (tp setPasswordR) mErr
    Nothing -> redirect $ tp loginR

getSetPasswordTokenR :: YesodAuthSimple master => Text -> AuthHandler master Html
getSetPasswordTokenR token = do
  res <- verifyPasswordResetToken token
  case res of
    Left msg -> invalidTokenHandler msg
    Right _ -> do
      tp <- getRouteToParent
      mErr <- getError
      authLayout $ do
        setTitle "Set password"
        setPasswordTemplate (tp $ setPasswordTokenR token) mErr

postSetPasswordTokenR :: YesodAuthSimple a => Text -> AuthHandler a Html
postSetPasswordTokenR token = do
  clearError
  (pass1, pass2) <- runInputPost $ (,)
    <$> ireq textField "password1"
    <*> ireq textField "password2"
  res <- verifyPasswordResetToken token
  case res of
    Left msg -> invalidTokenHandler msg
    Right uid -> setPasswordToken token uid pass1 pass2

putSetPasswordR :: YesodAuthSimple a => AuthHandler a Value
putSetPasswordR = do
  clearError
  uid <- requireAuthId
  passwords <- requireJsonBody :: (AuthHandler master) Passwords
  setPassword (toSimpleAuthId uid) passwords

setPassword :: YesodAuthSimple a => AuthSimpleId a -> Passwords -> AuthHandler a Value
setPassword uid passwords
  | passwordsOriginal passwords /= passwordsConfirm passwords = do
      let msg = "Passwords does not match" :: Text
      sendResponseStatus status400 $ object ["message" .= msg]
  | otherwise =
      case checkPasswordStrength (passwordsOriginal passwords) of
          Left msg ->
              sendResponseStatus status400 $ object ["message" .= msg]
          Right _ -> do
              salted <- liftIO $ saltPass (passwordsOriginal passwords)
              _ <- updateUserPassword uid salted
              onPasswordUpdated
              return $ object []

setPasswordToken :: YesodAuthSimple master => Text -> AuthSimpleId master -> Text -> Text -> AuthHandler master Html
setPasswordToken token uid pass1 pass2
  | pass1 /= pass2 = do
      setError "Passwords does not match"
      tp <- getRouteToParent
      redirect $ tp $ setPasswordTokenR token
  | otherwise =
      case checkPasswordStrength pass1 of
        Left msg -> do
          setError msg
          tp <- getRouteToParent
          redirect $ tp $ setPasswordTokenR token
        Right _ -> do
          salted <- liftIO $ saltPass pass1
          _ <- updateUserPassword uid salted
          onPasswordUpdated
          tp <- getRouteToParent
          redirect $ tp loginR

saltLength :: Int
saltLength = 5

-- | Salt a password with a randomly generated salt.
saltPass :: Text -> IO Text
saltPass = fmap (decodeUtf8With lenientDecode)
         . flip makePassword 17
         . encodeUtf8

saltPass' :: String -> String -> String
saltPass' salt pass =
  salt ++ T.unpack (decodeUtf8 $ B16.encode $ hash $ encodeUtf8 $ T.pack $ salt ++ pass)

isValidPass :: Text -- ^ cleartext password
            -> SaltedPass -- ^ salted password
            -> Bool
isValidPass ct salted =
  verifyPassword (encodeUtf8 ct) (encodeUtf8 salted) || isValidPass' ct salted

isValidPass' :: Text -- ^ cleartext password
            -> SaltedPass -- ^ salted password
            -> Bool
isValidPass' clear' salted' =
    let salt = take saltLength salted
     in salted == saltPass' salt clear
  where
    clear = T.unpack clear'
    salted = T.unpack salted'

verifyRegisterToken :: Text -> IO (Either Text Email)
verifyRegisterToken token = do
  res <- decryptRegisterToken token
  case res of
    Left msg -> return $ Left msg
    Right (expires, email) -> do
      now <- getCurrentTime
      if diffUTCTime expires now > 0
      then return $ Right email
      else return $ Left "Verification key has expired"

verifyPasswordResetToken :: YesodAuthSimple master => Text -> AuthHandler master (Either Text (AuthSimpleId master))
verifyPasswordResetToken token = do
  res <- decryptPasswordResetToken token
  case res of
    Left msg -> return $ Left msg
    Right (expires, modified, uid) -> do
      modifiedCurrent <- getUserModified uid
      now <- liftIO getCurrentTime
      if diffUTCTime expires now > 0 && modified == modifiedCurrent
      then return $ Right uid
      else return $ Left "Key has expired"

getDefaultKey :: IO CS.Key
getDefaultKey = CS.getKeyEnv "SESSION_KEY"

encryptPasswordResetToken :: YesodAuthSimple a => AuthSimpleId a -> UTCTime -> AuthHandler a Text
encryptPasswordResetToken uid modified = do
  expires <- liftIO $ addUTCTime 3600 <$> getCurrentTime
  key <- liftIO getDefaultKey
  let cleartext = T.concat [T.pack $ show expires, "|", T.pack $ show modified, "|", toPathPiece uid]
  ciphertext <- liftIO $ CS.encryptIO key $ encodeUtf8 cleartext
  return $ encodeToken ciphertext

decryptPasswordResetToken :: YesodAuthSimple master => Text -> AuthHandler master (Either Text (UTCTime, UTCTime, AuthSimpleId master))
decryptPasswordResetToken ciphertext = do
  key <- liftIO getDefaultKey
  case CS.decrypt key (decodeToken ciphertext) of
    Just bytes -> do
      let cleartext = decodeUtf8With lenientDecode bytes
      -- TODO: Fix this incomplete pattern
      let [expires, modified, uid] = T.splitOn "|" cleartext
      return $ Right (
          read $ T.unpack expires :: UTCTime,
          read $ T.unpack modified :: UTCTime,
          fromJust $ fromPathPiece uid)
    Nothing ->
      return $ Left "Failed to decode key"

encryptRegisterToken :: Email -> IO Text
encryptRegisterToken email = do
  expires <- addUTCTime 86400 <$> getCurrentTime
  key <- getDefaultKey
  let cleartext = T.intercalate "|" [ T.pack $ show expires, email ]
  ciphertext <- CS.encryptIO key $ encodeUtf8 cleartext
  return $ encodeToken ciphertext

decryptRegisterToken :: Text -> IO (Either Text (UTCTime, Email))
decryptRegisterToken ciphertext = do
  key <- getDefaultKey
  case CS.decrypt key (decodeToken ciphertext) of
    Just bytes -> do
      let cleartext = decodeUtf8With lenientDecode bytes
      let [expires, email] = T.splitOn "|" cleartext
      return $
        Right (read $ T.unpack expires :: UTCTime, email)
    Nothing ->
      return $ Left "Failed to decode key"

-- Re-encode to url-safe base64
encodeToken :: ByteString -> Text
encodeToken = decodeUtf8With lenientDecode . B64Url.encode . B64.decodeLenient

-- Re-encode to regular base64
decodeToken :: Text -> ByteString
decodeToken = B64.encode . B64Url.decodeLenient . encodeUtf8

redirectTemplate :: Route master -> WidgetFor master ()
redirectTemplate destUrl = [whamlet|
  $newline never
  <script>window.location = "@{destUrl}";
  <p>Content has moved, click
    <a href="@{destUrl}">here
|]

