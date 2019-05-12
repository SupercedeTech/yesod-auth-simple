{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE Rank2Types                 #-}
{-# LANGUAGE TypeFamilies               #-}

module Yesod.Auth.Simple
  ( -- * Plugin
    YesodAuthSimple(..)
  , authSimple
    -- * Routes
  , loginR
  , registerR
  , setPasswordR
  , resetPasswordR
  , resetPasswordEmailSentR
  , setPasswordTokenR
  , confirmR
  , userExistsR
  , registerSuccessR
  , confirmationEmailSentR
    -- * Default widgets
  , loginTemplateDef
  , setPasswordTemplateDef
  , invalidTokenTemplateDef
  , userExistsTemplateDef
  , registerSuccessTemplateDef
  , resetPasswordEmailSentTemplateDef
  , confirmationEmailSentTemplateDef
  , confirmTempateDef
  , resetPasswordTemplateDef
  , registerTemplateDef
    -- * Misc
  , encryptRegisterToken
    -- * Types
  , Email(..)
  , Password(..)
    -- * Re-export from Scrypt
  , EncryptedPass(..)
  , Pass(..)
  , encryptPassIO'
  ) where

import           Crypto.Scrypt                 (EncryptedPass (..), Pass (..),
                                                encryptPassIO', verifyPass')
import           Data.Aeson
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Base64        as B64
import qualified Data.ByteString.Base64.URL    as B64Url
import           Data.Function                 ((&))
import           Data.Maybe                    (fromJust)
import           Data.Text                     (Text)
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8With, encodeUtf8)
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.Time                     (UTCTime, addUTCTime,
                                                diffUTCTime, getCurrentTime)
import           Database.Persist.Sql          (PersistField, PersistFieldSql,
                                                PersistValue (PersistText),
                                                SqlType (SqlString),
                                                fromPersistValue, sqlType,
                                                toPersistValue)
import           Network.HTTP.Types            (badRequest400,
                                                unprocessableEntity422)
import           Network.Wai                   (responseBuilder)
import           Text.Blaze.Html.Renderer.Utf8 (renderHtmlBuilder)
import           Text.Email.Validate           (canonicalizeEmail)
import qualified Web.ClientSession             as CS
import           Yesod.Auth
import           Yesod.Core
import           Yesod.Form                    (ireq, runInputPost, textField)

newtype PassReq = PassReq { reqPass :: Text }

instance FromJSON PassReq where
  parseJSON = withObject "req" $ \o -> do
    pass <- o .: "pass"
    return $ PassReq pass

tshow :: Show a => a -> Text
tshow = T.pack . show

--------------------------------------------------------------------------------
confirmR :: Text -> AuthRoute
confirmR token = PluginR "simple" ["confirm", token]

confirmationEmailSentR :: AuthRoute
confirmationEmailSentR = PluginR "simple" ["confirmation-email-sent"]

loginR :: AuthRoute
loginR = PluginR "simple" ["login"]

registerR :: AuthRoute
registerR = PluginR "simple" ["register"]

registerSuccessR :: AuthRoute
registerSuccessR = PluginR "simple" ["register-success"]

resetPasswordEmailSentR :: AuthRoute
resetPasswordEmailSentR = PluginR "simple" ["reset-password-email-sent"]

resetPasswordR :: AuthRoute
resetPasswordR = PluginR "simple" ["reset-password"]

setPasswordR :: AuthRoute
setPasswordR = PluginR "simple" ["set-password"]

setPasswordTokenR :: Text -> AuthRoute
setPasswordTokenR token = PluginR "simple" ["set-password", token]

userExistsR :: AuthRoute
userExistsR = PluginR "simple" ["user-exists"]

--------------------------------------------------------------------------------
newtype Email = Email Text
  deriving Show

instance PersistFieldSql Email where
  sqlType = const SqlString

instance PersistField Email where
  toPersistValue (Email e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Email e
  fromPersistValue e               = Left $ "Not a PersistText: " <> tshow e

--------------------------------------------------------------------------------
newtype Password = Password Text

instance Show Password where
  show _ = "<redacted>"

instance PersistFieldSql Password where
  sqlType = const SqlString

instance PersistField Password where
  toPersistValue (Password e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Password e
  fromPersistValue e               = Left $ "Not a PersistText: " <> tshow e

--------------------------------------------------------------------------------
type VerUrl = Text

class (YesodAuth a, PathPiece (AuthSimpleId a)) => YesodAuthSimple a where
  type AuthSimpleId a

  afterPasswordRoute :: a -> Route a

  getUserId :: Email -> AuthHandler a (Maybe (AuthSimpleId a))

  getUserPassword :: AuthSimpleId a -> AuthHandler a EncryptedPass

  getUserModified :: AuthSimpleId a -> AuthHandler a UTCTime

  onRegisterSuccess :: AuthHandler a Html

  insertUser :: Email -> EncryptedPass -> AuthHandler a (Maybe (AuthSimpleId a))

  updateUserPassword :: AuthSimpleId a -> EncryptedPass -> AuthHandler a ()

  sendVerifyEmail :: Email -> VerUrl -> AuthHandler a ()
  sendVerifyEmail _ = liftIO . print

  sendResetPasswordEmail :: Email -> VerUrl -> AuthHandler a ()
  sendResetPasswordEmail _ = liftIO . print

  loginTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  loginTemplate = loginTemplateDef

  registerTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  registerTemplate = registerTemplateDef

  resetPasswordTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  resetPasswordTemplate = resetPasswordTemplateDef

  confirmTemplate :: Route a -> Email -> Maybe Text -> WidgetFor a ()
  confirmTemplate = confirmTempateDef

  confirmationEmailSentTemplate :: WidgetFor a ()
  confirmationEmailSentTemplate = confirmationEmailSentTemplateDef

  resetPasswordEmailSentTemplate :: WidgetFor a ()
  resetPasswordEmailSentTemplate = resetPasswordEmailSentTemplateDef

  registerSuccessTemplate :: WidgetFor a ()
  registerSuccessTemplate = registerSuccessTemplateDef

  userExistsTemplate :: WidgetFor a ()
  userExistsTemplate = userExistsTemplateDef

  invalidTokenTemplate :: Text -> WidgetFor a ()
  invalidTokenTemplate = invalidTokenTemplateDef

  setPasswordTemplate :: Route a -> Maybe Text -> WidgetFor a ()
  setPasswordTemplate = setPasswordTemplateDef

  onPasswordUpdated :: AuthHandler a ()
  onPasswordUpdated = setMessage "Password has been updated"

authSimple :: YesodAuthSimple m => AuthPlugin m
authSimple = AuthPlugin "simple" dispatch loginHandlerRedirect

loginHandlerRedirect :: (Route Auth -> Route a) -> WidgetFor a ()
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

getRegisterR :: YesodAuthSimple a => AuthHandler a Html
getRegisterR = do
  mErr <- getError
  muid <- maybeAuthId
  tp   <- getRouteToParent
  case muid of
    Nothing -> authLayout $ do
      setTitle "Register a new account"
      registerTemplate tp mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

getResetPasswordR :: YesodAuthSimple a => AuthHandler a Html
getResetPasswordR = do
  mErr <- getError
  tp   <- getRouteToParent
  authLayout $ do
    setTitle "Reset password"
    resetPasswordTemplate tp mErr

getLoginR :: YesodAuthSimple a => AuthHandler a Html
getLoginR = do
  mErr <- getError
  muid <- maybeAuthId
  tp   <- getRouteToParent
  case muid of
    Nothing -> authLayout $ do
      setTitle "Login"
      loginTemplate tp mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

postRegisterR :: YesodAuthSimple a => AuthHandler a Html
postRegisterR = do
  clearError
  email <- runInputPost $ ireq textField "email"
  mEmail <- validateAndNormalizeEmail email
  case mEmail of
    Just email' -> do
      token <- liftIO $ encryptRegisterToken (Email email')
      tp <- getRouteToParent
      renderUrl <- getUrlRender
      let url = renderUrl $ tp $ confirmR token
      sendVerifyEmail (Email email') url
      redirect $ tp confirmationEmailSentR
    Nothing -> do
      setError "Invalid email address"
      tp <- getRouteToParent
      redirectWith unprocessableEntity422 $ tp registerR

postResetPasswordR :: YesodAuthSimple a => AuthHandler a Html
postResetPasswordR = do
  clearError
  email <- runInputPost $ ireq textField "email"
  mUid  <- getUserId $ Email $ normalizeEmail email
  case mUid of
    Just uid -> do
      modified <- getUserModified uid
      token <- encryptPasswordResetToken uid modified
      tp <- getRouteToParent
      renderUrl <- getUrlRender
      let url = renderUrl $ tp $ setPasswordTokenR token
      sendResetPasswordEmail (Email email) url
      redirect $ tp resetPasswordEmailSentR
    Nothing -> do
      setError "Email not found"
      tp <- getRouteToParent
      redirect $ tp resetPasswordR

getConfirmR :: YesodAuthSimple a => Text -> AuthHandler a Html
getConfirmR token = do
  res <- liftIO $ verifyRegisterToken token
  case res of
    Left msg    -> invalidTokenHandler msg
    Right email -> confirmHandlerHelper token email

invalidTokenHandler :: YesodAuthSimple a => Text -> AuthHandler a Html
invalidTokenHandler msg = do
  html <- authLayout $ do
    setTitle "Invalid key"
    invalidTokenTemplate msg
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder badRequest400 contentType
    & sendWaiResponse

confirmHandlerHelper :: YesodAuthSimple a => Text -> Email -> AuthHandler a Html
confirmHandlerHelper token email = do
  tp <- getRouteToParent
  confirmHandler (tp $ confirmR token) email

confirmHandler :: YesodAuthSimple a => Route a -> Email -> AuthHandler a Html
confirmHandler registerUrl email = do
  mErr <- getError
  authLayout $ do
    setTitle "Confirm account"
    confirmTemplate registerUrl email mErr

postConfirmR :: YesodAuthSimple a => Text -> AuthHandler a Html
postConfirmR token = do
  clearError
  pass <- runInputPost $ ireq textField "password"
  res  <- liftIO $ verifyRegisterToken token
  case res of
    Left msg ->
      invalidTokenHandler msg
    Right email ->
      createUser token email (Pass . encodeUtf8 $ pass)

createUser :: YesodAuthSimple m => Text -> Email -> Pass -> AuthHandler m Html
createUser token email pass = case checkPasswordStrength pass of
  Left msg -> do
    setError msg
    tp <- getRouteToParent
    redirectWith unprocessableEntity422 $ tp $ confirmR token
  Right _ -> do
    encrypted <- liftIO $ encryptPassIO' pass
    mUid      <- insertUser email encrypted
    case mUid of
      Just uid -> do
        let creds = Creds "simple" (toPathPiece uid) []
        setCreds False creds
        onRegisterSuccess
      Nothing -> do
        tp <- getRouteToParent
        redirect $ tp userExistsR

getConfirmationEmailSentR :: YesodAuthSimple a => AuthHandler a Html
getConfirmationEmailSentR = authLayout $ do
  setTitle "Confirmation email sent"
  confirmationEmailSentTemplate

getResetPasswordEmailSentR :: YesodAuthSimple a => AuthHandler a Html
getResetPasswordEmailSentR = authLayout $ do
  setTitle "Reset password email sent"
  resetPasswordEmailSentTemplate

getRegisterSuccessR :: AuthHandler a Html
getRegisterSuccessR = do
  setMessage "Account created. Welcome!"
  redirect ("/" :: Text)

getUserExistsR :: YesodAuthSimple a => AuthHandler a Html
getUserExistsR = authLayout $ do
  setTitle "User already exists"
  userExistsTemplate

checkPasswordStrength :: Pass -> Either Text ()
checkPasswordStrength x
  | BS.length (getPass x) >= 8 = Right ()
  | otherwise = Left "Password must be at least eight characters"

normalizeEmail :: Text -> Text
normalizeEmail = T.toLower

validateAndNormalizeEmail :: Text -> AuthHandler a (Maybe Text)
validateAndNormalizeEmail email = case canonicalizeEmail $ encodeUtf8 email of
  Just bytes ->
      return $ Just $ normalizeEmail $ decodeUtf8With lenientDecode bytes
  Nothing -> return Nothing

getError :: AuthHandler a (Maybe Text)
getError = do
  mErr <- lookupSession "error"
  clearError
  return mErr

setError :: Text -> AuthHandler a ()
setError = setSession "error"

clearError :: AuthHandler a ()
clearError = deleteSession "error"

postLoginR :: YesodAuthSimple a => AuthHandler a TypedContent
postLoginR = do
  clearError
  (email, pass') <- runInputPost $ (,)
    <$> ireq textField "email"
    <*> ireq textField "password"
  let pass = Pass . encodeUtf8 $ pass'
  mUid <- getUserId (Email email)
  case mUid of
    Just uid -> do
      realPass <- getUserPassword uid
      if verifyPass' pass realPass
      then setCredsRedirect $ Creds "simple" (toPathPiece uid) []
      else wrongEmailOrPasswordRedirect
    _ -> wrongEmailOrPasswordRedirect

wrongEmailOrPasswordRedirect :: AuthHandler a TypedContent
wrongEmailOrPasswordRedirect = do
  setError "Wrong email or password"
  tp <- getRouteToParent
  redirect $ tp loginR

toSimpleAuthId :: forall c a. (PathPiece c, PathPiece a) => a -> c
toSimpleAuthId = fromJust . fromPathPiece . toPathPiece

getSetPasswordR :: YesodAuthSimple a => AuthHandler a Html
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

getSetPasswordTokenR :: YesodAuthSimple a => Text -> AuthHandler a Html
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
  pass <- runInputPost $ ireq textField "password"
  res  <- verifyPasswordResetToken token
  case res of
    Left msg  -> invalidTokenHandler msg
    Right uid -> setPassToken token uid (Pass . encodeUtf8 $ pass)

putSetPasswordR :: YesodAuthSimple a => AuthHandler a Value
putSetPasswordR = do
  clearError
  uid <- toSimpleAuthId <$> requireAuthId
  req <- requireJsonBody :: (AuthHandler m) PassReq
  let pass = Pass . encodeUtf8 $ reqPass req
  setPassword uid pass

setPassword :: YesodAuthSimple a => AuthSimpleId a -> Pass -> AuthHandler a Value
setPassword uid pass = case checkPasswordStrength pass of
  Left msg -> sendResponseStatus unprocessableEntity422 $ object [ "message" .= msg ]
  Right _  -> do
    encrypted <- liftIO $ encryptPassIO' pass
    _         <- updateUserPassword uid encrypted
    onPasswordUpdated
    return $ object []

setPassToken :: YesodAuthSimple a
             => Text
             -> AuthSimpleId a
             -> Pass
             -> AuthHandler a Html
setPassToken token uid pass = case checkPasswordStrength pass of
  Left msg -> do
    setError msg
    tp <- getRouteToParent
    redirectWith unprocessableEntity422 $ tp $ setPasswordTokenR token
  Right _ -> do
    encrypted <- liftIO $ encryptPassIO' pass
    _         <- updateUserPassword uid encrypted
    onPasswordUpdated
    tp <- getRouteToParent
    redirect $ tp loginR

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

verifyPasswordResetToken :: YesodAuthSimple a => Text -> AuthHandler a (Either Text (AuthSimpleId a))
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
  let cleartext = T.intercalate "|" [tshow expires, tshow modified, toPathPiece uid]
  ciphertext <- liftIO $ CS.encryptIO key $ encodeUtf8 cleartext
  return $ encodeToken ciphertext

decryptPasswordResetToken :: YesodAuthSimple a => Text -> AuthHandler a (Either Text (UTCTime, UTCTime, AuthSimpleId a))
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
encryptRegisterToken (Email email) = do
  expires <- addUTCTime 86400 <$> getCurrentTime
  key <- getDefaultKey
  let cleartext = T.intercalate "|" [ tshow expires, email ]
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
        Right (read $ T.unpack expires :: UTCTime, (Email email))
    Nothing ->
      return $ Left "Failed to decode key"

-- Re-encode to url-safe base64
encodeToken :: ByteString -> Text
encodeToken = decodeUtf8With lenientDecode . B64Url.encode . B64.decodeLenient

-- Re-encode to regular base64
decodeToken :: Text -> ByteString
decodeToken = B64.encode . B64Url.decodeLenient . encodeUtf8

redirectTemplate :: Route a -> WidgetFor a ()
redirectTemplate destUrl = [whamlet|
  $newline never
  <script>window.location = "@{destUrl}";
  <p>Content has moved, click
    <a href="@{destUrl}">here
|]

loginTemplateDef :: YesodAuthSimple a => (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
loginTemplateDef toParent mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <h1>Sign in
  <form method="post" action="@{toParent loginR}">
    <fieldset>
      <label for="email">Email
      <input type="email" name="email" autofocus required>
    <fieldset>
      <label for="pass">Password
      <input type="password" name="pass" required>
    <button type="submit">Sign in
    <p>
      <a href="@{toParent resetPasswordR}">Forgot password?
    <p class="need-to-register">
      Need an account? <a href="@{toParent registerR}">Register</a>.
  |]

setPasswordTemplateDef :: YesodAuthSimple a => Route a -> Maybe Text -> WidgetFor a ()
setPasswordTemplateDef url mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <h1>Set new password
  <form method="post" action="@{url}">
    <fieldset>
      <label for="pass">Password
      <input type="password" name="pass" autofocus required>
    <button type="submit">Save
  |]

invalidTokenTemplateDef :: YesodAuthSimple a => Text -> WidgetFor a ()
invalidTokenTemplateDef msg = [whamlet|
  $newline never
  <.invalid-token>
    <h1>Invalid key
    <p>#{msg}
|]

userExistsTemplateDef :: YesodAuthSimple a => WidgetFor a ()
userExistsTemplateDef = [whamlet|
  $newline never
  <.user-exists>
    <h1>Failed to create account
    <p>User already exists
|]

registerSuccessTemplateDef :: YesodAuthSimple a => WidgetFor a ()
registerSuccessTemplateDef = [whamlet|
  $newline never
  <.register-success>
    <h1>Account created!
|]

resetPasswordEmailSentTemplateDef :: YesodAuthSimple a => WidgetFor a ()
resetPasswordEmailSentTemplateDef = [whamlet|
  $newline never
  <.password-reset-email-sent>
    <h1>Email Sent!
    <p>An email has been sent to your address.
    <p>Click on the link in the email to complete the password reset.
|]

confirmationEmailSentTemplateDef :: YesodAuthSimple a => WidgetFor a ()
confirmationEmailSentTemplateDef = [whamlet|
  $newline never
  <.confirmation-email-sent">
    <h1>Email sent
    <p>
      A confirmation email has been sent to your address.
      Click on the link in the email to complete the registration.
|]

confirmTempateDef :: Route a -> Email -> Maybe Text -> WidgetFor a ()
confirmTempateDef confirmUrl (Email email) mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <.confirm>
    <h1>Set Your Password
    <form method="post" action="@{confirmUrl}">
      <p>#{email}
      <fieldset>
        <label for="pass">Password
        <input type="password" name="pass" placeholder="Easy to remember, hard to guess" required autofocus>
      <button type="submit">Set Password
|]

resetPasswordTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
resetPasswordTemplateDef toParent mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <.reset-password>
    <h1>Reset Password
    <p>Did you forget your password? No problem.
    <p>Give us your email address, and we'll send you reset instructions.
    <form method="post" action="@{toParent resetPasswordR}">
      <fieldset>
        <label for="email">Email
        <input type="email" name="email" autofocus required>
      <button type="submit">Reset
|]

registerTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
registerTemplateDef toParent mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <.register>
    <h1>Register new account
    <form method="post" action="@{toParent registerR}">
      <fieldset>
        <label for="email">Email
        <input type="email" name="email" placeholder="Enter your email address" autofocus required>
      <button type="submit">Register
      <p>Already have an account? <a href="@{toParent loginR}">Sign in</a>.
|]

