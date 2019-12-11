{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE Rank2Types          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}

-- | A Yesod plugin for traditional email/password authentication
--
-- This plugin uses an alternative flow to Yesod.Auth.Email fom the yesod-auth
-- package.

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
  , passwordStrengthR
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
  , passwordFieldTemplateBasic
  , passwordFieldTemplateZxcvbn
    -- * Misc
  , encryptRegisterToken
  , maxPasswordLength
    -- * Types
  , Email(..)
  , Password(..)
  , PW.Strength(..)
  , PasswordCheck(..)
    -- * Re-export from Scrypt
  , EncryptedPass(..)
  , Pass(..)
  , encryptPassIO'
  ) where

import           ClassyPrelude
import           Crypto.Scrypt                 (EncryptedPass (..), Pass (..),
                                                encryptPassIO', verifyPass')
import           Data.Aeson
import           Data.ByteString               (ByteString)
import qualified Data.ByteString.Base64        as B64
import qualified Data.ByteString.Base64.URL    as B64Url
import           Data.Function                 ((&))
import           Data.Maybe                    (fromJust)
import           Data.Text                     (Text)
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8', decodeUtf8With)
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.Time                     (Day, UTCTime (..), addUTCTime,
                                                diffUTCTime, getCurrentTime)
import           Data.Vector                   (Vector)
import qualified Data.Vector                   as Vec
import           Network.HTTP.Types            (badRequest400)
import           Network.Wai                   (responseBuilder)
import           Text.Blaze.Html.Renderer.Utf8 (renderHtmlBuilder)
import           Text.Email.Validate           (canonicalizeEmail)
import qualified Text.Password.Strength        as PW
import qualified Text.Password.Strength.Config as PW
import qualified Web.ClientSession             as CS
import           Yesod.Auth
import           Yesod.Auth.Simple.Types
import           Yesod.Core
import           Yesod.Core.Json               as J
import           Yesod.Form                    (ireq, runInputPost, textField)

minPasswordLength :: Int
minPasswordLength = 8 -- min length required in NIST SP 800-63B

maxPasswordLength :: Int
maxPasswordLength = 150 -- zxcvbn takes too long after this point

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

passwordStrengthR :: AuthRoute
passwordStrengthR = PluginR "simple" ["password-strength"]

class (YesodAuth a, PathPiece (AuthSimpleId a)) => YesodAuthSimple a where
  type AuthSimpleId a

  afterPasswordRoute :: a -> Route a

  getUserId :: Email -> AuthHandler a (Maybe (AuthSimpleId a))

  getUserPassword :: AuthSimpleId a -> AuthHandler a EncryptedPass

  getUserModified :: AuthSimpleId a -> AuthHandler a UTCTime

  onRegisterSuccess :: AuthHandler a TypedContent

  insertUser :: Email -> EncryptedPass -> AuthHandler a (Maybe (AuthSimpleId a))

  updateUserPassword :: AuthSimpleId a -> EncryptedPass -> AuthHandler a ()

  sendVerifyEmail :: Email -> VerUrl -> AuthHandler a ()
  sendVerifyEmail _ = liftIO . print

  sendResetPasswordEmail :: Email -> VerUrl -> AuthHandler a ()
  sendResetPasswordEmail _ = liftIO . print

  passwordFieldTemplate :: (AuthRoute -> Route a) -> WidgetFor a ()
  passwordFieldTemplate tp =
    case passwordCheck @a of
      Zxcvbn minStren extraWords' -> passwordFieldTemplateZxcvbn tp minStren extraWords'
      RuleBased _ -> passwordFieldTemplateBasic

  loginTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  loginTemplate = loginTemplateDef

  registerTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  registerTemplate = registerTemplateDef

  resetPasswordTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  resetPasswordTemplate = resetPasswordTemplateDef

  confirmTemplate :: (AuthRoute -> Route a) -> Route a -> Email -> Maybe Text -> WidgetFor a ()
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

  setPasswordTemplate :: (AuthRoute -> Route a) -> Route a -> Maybe Text -> WidgetFor a ()
  setPasswordTemplate = setPasswordTemplateDef

  onPasswordUpdated :: AuthHandler a ()
  onPasswordUpdated = setMessage "Password has been updated"

  passwordCheck :: PasswordCheck
  passwordCheck = Zxcvbn PW.Safe Vec.empty

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
-- NB: We use a POST instead of GET so that we don't send the password
-- in the URL query string
dispatch "POST" ["password-strength"] = postPasswordStrengthR >>= sendResponse
dispatch _ _ = notFound

getRegisterR :: YesodAuthSimple a => AuthHandler a TypedContent
getRegisterR = do
  mErr <- getError
  muid <- maybeAuthId
  tp   <- getRouteToParent
  case muid of
    Nothing -> selectRep . provideRep . authLayout $ do
      setTitle "Register a new account"
      registerTemplate tp mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

getResetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
getResetPasswordR = do
  mErr <- getError
  tp   <- getRouteToParent
  selectRep . provideRep . authLayout $ do
    setTitle "Reset password"
    resetPasswordTemplate tp mErr

getLoginR :: YesodAuthSimple a => AuthHandler a TypedContent
getLoginR = do
  mErr <- getError
  muid <- maybeAuthId
  tp   <- getRouteToParent
  case muid of
    Nothing -> selectRep . provideRep . authLayout $ do
      setTitle "Login"
      loginTemplate tp mErr
    Just _ -> redirect $ toPathPiece ("/" :: String)

postRegisterR :: YesodAuthSimple a => AuthHandler a TypedContent
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
      redirect $ tp registerR

postResetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
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

getConfirmR :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
getConfirmR token =
  liftIO (verifyRegisterToken token) >>= either verifyFail verifySucc
  where
    verifyFail = invalidTokenHandler
    verifySucc email = getUserId email >>=
                         maybe (doConfirm email) redirectToHome
    redirectToHome uid = setCredsRedirect $ Creds "simple" (toPathPiece uid) []
    doConfirm = confirmHandlerHelper token

invalidTokenHandler :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
invalidTokenHandler msg = do
  html <- authLayout $ do
    setTitle "Invalid key"
    invalidTokenTemplate msg
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder badRequest400 contentType
    & sendWaiResponse

confirmHandlerHelper :: YesodAuthSimple a => Text -> Email -> AuthHandler a TypedContent
confirmHandlerHelper token email = do
  tp <- getRouteToParent
  confirmHandler (tp $ confirmR token) email

confirmHandler :: YesodAuthSimple a => Route a -> Email -> AuthHandler a TypedContent
confirmHandler registerUrl email = do
  mErr <- getError
  tp <- getRouteToParent
  selectRep . provideRep . authLayout $ do
    setTitle "Confirm account"
    confirmTemplate tp registerUrl email mErr

postConfirmR :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
postConfirmR token = do
  clearError
  password <- runInputPost $ ireq textField "password"
  res  <- liftIO $ verifyRegisterToken token
  case res of
    Left msg ->
      invalidTokenHandler msg
    Right email ->
      createUser token email (Pass . encodeUtf8 $ password)

createUser :: forall m. YesodAuthSimple m => Text -> Email -> Pass -> AuthHandler m TypedContent
createUser token email password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @m) password
  case check of
    Left msg -> do
      setError msg
      tp <- getRouteToParent
      redirect $ tp $ confirmR token
    Right _ -> do
      encrypted <- liftIO $ encryptPassIO' password
      mUid      <- insertUser email encrypted
      case mUid of
        Just uid -> do
          let creds = Creds "simple" (toPathPiece uid) []
          setCreds False creds
          onRegisterSuccess
        Nothing -> do
          tp <- getRouteToParent
          redirect $ tp userExistsR

getConfirmationEmailSentR :: YesodAuthSimple a => AuthHandler a TypedContent
getConfirmationEmailSentR = selectRep . provideRep . authLayout $ do
  setTitle "Confirmation email sent"
  confirmationEmailSentTemplate

getResetPasswordEmailSentR :: YesodAuthSimple a => AuthHandler a TypedContent
getResetPasswordEmailSentR = selectRep . provideRep . authLayout $ do
  setTitle "Reset password email sent"
  resetPasswordEmailSentTemplate

getRegisterSuccessR :: AuthHandler a TypedContent
getRegisterSuccessR = do
  setMessage "Account created. Welcome!"
  redirect ("/" :: Text)

getUserExistsR :: YesodAuthSimple a => AuthHandler a TypedContent
getUserExistsR = selectRep . provideRep . authLayout $ do
  setTitle "User already exists"
  userExistsTemplate

postPasswordStrengthR :: forall a. (YesodAuthSimple a) => AuthHandler a J.Value
postPasswordStrengthR = do
  password <- runInputPost (ireq textField "password")
  let pass = Pass . encodeUtf8 $ password
  liftIO $ toJSON <$> checkPasswordStrength (passwordCheck @a) pass

checkPassWithZxcvbn :: PW.Strength -> Vector Text -> Day -> Text -> PasswordStrength
checkPassWithZxcvbn minStrength' extraWords' day password =
  let conf = PW.addCustomFrequencyList extraWords' PW.en_US
      guesses = PW.score conf day password
      stren = PW.strength guesses
  in if stren >= minStrength' then GoodPassword stren
     else BadPassword stren $ Just "The password is not strong enough"

checkPassWithRules :: Int -> Text -> PasswordStrength
checkPassWithRules minLen password
  | T.length password >= minLen = GoodPassword PW.Safe
  | otherwise = BadPassword PW.Weak . Just . T.pack
                $ "Password must be at least " <> show minLen <> " characters"

strengthToEither :: PasswordStrength -> Either Text PW.Strength
strengthToEither (GoodPassword stren) = Right stren
strengthToEither (BadPassword _ (Just err)) = Left err
strengthToEither (BadPassword _ Nothing) =
  Left "The password is not strong enough"

getPWStrength :: PasswordStrength -> PW.Strength
getPWStrength (GoodPassword stren)  = stren
getPWStrength (BadPassword stren _) = stren

checkPasswordStrength :: PasswordCheck -> Pass -> IO PasswordStrength
checkPasswordStrength check pass =
  case decodeUtf8' (getPass pass) of
    Left _  -> pure $ BadPassword PW.Weak $ Just "Invalid characters in password"
    Right password ->
      if not satisfiesMaxLen
      then pure . BadPassword PW.Weak . Just
           $ "Password exceeds maximum length of "
           <> T.pack (show maxPasswordLength)
      else case check of
        RuleBased minLen ->
          pure $ checkPassWithRules (max minLen minPasswordLength) password
        Zxcvbn minStren extraWords' -> do
          today <- utctDay <$> getCurrentTime
          let pwstren = checkPassWithZxcvbn minStren extraWords' today password
          pure $
            if satisfiesMinLen
            then pwstren
            -- Although we always prevent passwords below the minimum
            -- length, we do not score it as Weak invariably. This
            -- prevents the password meter from sticking at the lowest
            -- level until after you input a safe password of min length
            else BadPassword (min (getPWStrength pwstren) (pred minStren))
                 . Just $ "The password must be at least "
                 <> T.pack (show minPasswordLength) <> " characters"
      where (boundedPw, extra) = T.splitAt maxPasswordLength password
            satisfiesMinLen = T.length boundedPw >= minPasswordLength
            satisfiesMaxLen = T.null extra

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
  (email, password') <- runInputPost $ (,)
    <$> ireq textField "email"
    <*> ireq textField "password"
  let password = Pass . encodeUtf8 $ password'
  mUid <- getUserId (Email email)
  case mUid of
    Just uid -> do
      storedPassword <- getUserPassword uid
      if verifyPass' password storedPassword
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

getSetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
getSetPasswordR = do
  mUid <- maybeAuthId
  tp <- getRouteToParent
  case mUid of
    Just _ -> do
      mErr <- getError
      selectRep . provideRep . authLayout $ do
        setTitle "Set password"
        setPasswordTemplate tp (tp setPasswordR) mErr
    Nothing -> redirect $ tp loginR

getSetPasswordTokenR :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
getSetPasswordTokenR token = do
  res <- verifyPasswordResetToken token
  case res of
    Left msg -> invalidTokenHandler msg
    Right _ -> do
      tp <- getRouteToParent
      mErr <- getError
      selectRep . provideRep . authLayout $ do
        setTitle "Set password"
        setPasswordTemplate tp (tp $ setPasswordTokenR token) mErr

-- | Set a new password for the user
postSetPasswordTokenR :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
postSetPasswordTokenR token = do
  clearError
  password <- runInputPost $ ireq textField "password"
  res  <- verifyPasswordResetToken token
  case res of
    Left msg  -> invalidTokenHandler msg
    Right uid -> setPassToken token uid (Pass . encodeUtf8 $ password)

putSetPasswordR :: YesodAuthSimple a => AuthHandler a Value
putSetPasswordR = do
  clearError
  uid <- toSimpleAuthId <$> requireAuthId
  req <- requireCheckJsonBody :: (AuthHandler m) PasswordReq
  let password = Pass . encodeUtf8 $ unPasswordReq req
  setPassword uid password

setPassword :: forall a. YesodAuthSimple a => AuthSimpleId a -> Pass -> AuthHandler a Value
setPassword uid password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @a) password
  case check of
    Left msg -> sendResponseStatus badRequest400 $ object [ "message" .= msg ]
    Right _  -> do
      encrypted <- liftIO $ encryptPassIO' password
      _         <- updateUserPassword uid encrypted
      onPasswordUpdated
      return $ object []

setPassToken
  :: forall a. YesodAuthSimple a
  => Text
  -> AuthSimpleId a
  -> Pass
  -> AuthHandler a TypedContent
setPassToken token uid password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @a) password
  case check of
    Left msg -> do
      setError msg
      tp <- getRouteToParent
      redirect $ tp $ setPasswordTokenR token
    Right _ -> do
      encrypted <- liftIO $ encryptPassIO' password
      _         <- updateUserPassword uid encrypted
      onPasswordUpdated
      setCredsRedirect $ Creds "simple" (toPathPiece uid) []

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

verifyPasswordResetToken
  :: YesodAuthSimple a
  => Text
  -> AuthHandler a (Either Text (AuthSimpleId a))
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

encryptPasswordResetToken
  :: YesodAuthSimple a
  => AuthSimpleId a
  -> UTCTime
  -> AuthHandler a Text
encryptPasswordResetToken uid modified = do
  expires <- liftIO $ addUTCTime 3600 <$> getCurrentTime
  key <- liftIO getDefaultKey
  let cleartext = T.intercalate "|" [tshow expires, tshow modified, toPathPiece uid]
  ciphertext <- liftIO $ CS.encryptIO key $ encodeUtf8 cleartext
  return $ encodeToken ciphertext

decryptPasswordResetToken
  :: YesodAuthSimple a
  => Text
  -> AuthHandler a (Either Text (UTCTime, UTCTime, AuthSimpleId a))
decryptPasswordResetToken ciphertext = do
  key <- liftIO getDefaultKey
  case CS.decrypt key (decodeToken ciphertext) of

    Just bytes -> case T.splitOn "|" (decodeUtf8With lenientDecode bytes) of
      [expires, modified, uid] -> return . toEither $ do
        e <- readMay $ unpack expires
        m <- readMay $ unpack modified
        u <- fromPathPiece uid
        Just (e, m, u)

      _ -> return err

    Nothing -> return err
  where
    err = Left "Failed to decode key"
    toEither = \case
      Just v -> Right v
      Nothing -> err

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
    Just bytes -> case T.splitOn "|" (decodeUtf8With lenientDecode bytes) of
      [expires, email] -> return . toEither $ do
        e <- readMay (unpack expires) :: Maybe UTCTime
        Just (e, Email email)
      _ -> return err
    Nothing -> return err
  where
    err = Left "Failed to decode key"
    toEither = \case
      Just v -> Right v
      Nothing -> err

-- Re-encode to url-safe base64
encodeToken :: ByteString -> Text
encodeToken = decodeUtf8With lenientDecode . B64Url.encode . B64.decodeLenient

-- Re-encode to regular base64
decodeToken :: Text -> ByteString
decodeToken = B64.encode . B64Url.decodeLenient . encodeUtf8

redirectTemplate :: Route a -> WidgetFor a ()
redirectTemplate destUrl = do
  toWidget
    [whamlet|
      $newline never
      <p>Content has moved, click
        <a href="@{destUrl}">here
    |]
  toWidget
    [julius|window.location = "@{destUrl}";|]

loginTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
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
      <label for="password">Password
      <input type="password" name="password" required>
    <button type="submit">Sign in
    <p>
      <a href="@{toParent resetPasswordR}">Forgot password?
    <p class="need-to-register">
      Need an account? <a href="@{toParent registerR}">Register</a>.
  |]

passwordFieldTemplateBasic :: WidgetFor a ()
passwordFieldTemplateBasic = [whamlet|
  $newline never
  <fieldset>
    <label for="password">Password
    <input type="password" name="password" autofocus required>
  |]

zxcvbnJsUrl :: Text
zxcvbnJsUrl = "https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js"

passwordFieldTemplateZxcvbn :: (AuthRoute -> Route a) -> PW.Strength -> Vector Text -> WidgetFor a ()
passwordFieldTemplateZxcvbn toParent minStren extraWords' = do
  let extraWordsStr = T.unwords . toList $ extraWords'
      blankPasswordScore = BadPassword PW.Risky Nothing
  addScriptRemote zxcvbnJsUrl
  toWidget
    [hamlet|
      $newline never
      <fieldset>
        <label for="password">Password
        <input#password type="password" name="password" autofocus required>
        <#yas--extra-words data-extra-words="#{extraWordsStr}">
        <#yas--password-feedback>
          <.yas--password-meter-container>
            <.yas--password-meter.yas--strength-init>
          <.yas--password-errors>
            <p.yas--password-warning>
            <.yas--password-suggestions>
     |]
  toWidget
    [lucius|
      .yas--extra-words { display: none; }
      .yas--password-meter-container {
        height: 5px;
        background-color: #C7C7C7;
        .yas--password-meter {
          height: 100%;
          transition: background-color 1s, margin-right 1s;
        }
        .yas--password-meter.yas--strength-init {
          margin-right: 100%;
        }
        .yas--password-meter.yas--strength-0 {
          background-color: #ff0000;
          margin-right: 90%;
        }
        .yas--password-meter.yas--strength-1 {
          background-color: #ff0000;
          margin-right: 75%;
        }
        .yas--password-meter.yas--strength-2 {
          background-color: #ffa500;
          margin-right: 50%;
        }
        .yas--password-meter.yas--strength-3 {
          background-color: #008000;
          margin-right: 25%;
        }
        .yas--password-meter.yas--strength-4 {
          background-color: #008000;
          margin-right: 0%;
        }
       }
       .yas--password-suggestions ul {
         margin-left: 2em;
         margin-bottom: 0;
         list-style: disc;
         font-size: 90%;
       }
    |]
  toWidget
    [julius|
      var yas__extraWordsEl = document.getElementById("yas__extra-words");
      var yas__extraWords = [];
      if (yas__extraWordsEl) {
        var str = yas__extraWordsEl.getAttribute("data-extra-words");
        if (Boolean(str)) { yas__extraWords = str.split(" "); }
      }

      var yas__passwordFeedback = document.getElementById("yas--password-feedback");
      var yas__passwordMeter = yas__passwordFeedback.querySelector(".yas--password-meter");
      var yas__passwordErrors = yas__passwordFeedback.querySelector(".yas--password-errors");

      function yas_showError() {
        var warningEl = yas__passwordErrors.querySelector(".yas--password-warning");
        warningEl.appendChild(document.createTextNode("Error requesting password strength"));
      }

      function yas_updateFeedback (password, strength) {
        var gotScore = typeof strength.score === "number";
        var score, feedback, jsResult;
        if (!gotScore || strength.score <= 2 || strength.score < #{toJSON $ fromEnum minStren}) {
          jsResult = zxcvbn(password, yas__extraWords);
          feedback = jsResult.feedback;
        }

        if (gotScore) { score = strength.score; }
        else {          score = jsResult.score; }

        yas__passwordMeter.classList.add("yas--strength-" + score);
        yas__passwordMeter.classList.remove("yas--strength-init");
        for (var i=0; i<5; i++) {
          if (i !== score) {
            yas__passwordMeter.classList.remove("yas--strength-" + i);
          }
        }

        var warningEl = yas__passwordErrors.querySelector(".yas--password-warning");
        while (warningEl.firstChild) { warningEl.removeChild(warningEl.firstChild); }

        var tips = yas__passwordErrors.querySelector(".yas--password-suggestions");
        while (tips && tips.firstChild) { tips.removeChild(tips.firstChild); }

        if (Boolean(password) && score < #{toJSON $ fromEnum minStren}) {
          var warning;
          if (Boolean(strength.error)) {
            warning = strength.error;
          } else {
            warning = "The password is not strong enough";
          }
          if (Boolean(feedback.warning)) {
            warning = warning + ". " + feedback.warning;
          }
          warningEl.appendChild(document.createTextNode(warning));

          if (feedback.suggestions.length > 0) {
            var suggestionList = document.createElement("ul");
            for (var i=0; i<feedback.suggestions.length; i++) {
              var li = document.createElement("li");
              var txt = document.createTextNode(feedback.suggestions[i]);
              li.classList.add("yas--suggestion");
              li.appendChild(txt);
              suggestionList.appendChild(li);
            }
            tips.appendChild(suggestionList);
          }
        }
      }

      var yas_currentReq = 0;
      function yas_getPasswordStrength(password) {
        var req = new XMLHttpRequest();
        var reqNum = yas_currentReq + 1;
        req.onreadystatechange = function(resp) {
          if (req.readyState === XMLHttpRequest.DONE) {
            if (req.status === 200) {
              var resp = JSON.parse(req.responseText);
              if (reqNum <= yas_currentReq) {
                yas_updateFeedback(password, resp);
              }
            } else {
              yas_updateFeedback("", #{toJSON blankPasswordScore});
              yas_showError();
            }
          }
        };
        req.open("POST", "@{toParent passwordStrengthR}", true);
        req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        req.send("password=" + encodeURIComponent(password));
        yas_currentReq += 1;
      }

      function yas_debounce(delay, fn) {
        var timeout;
        return function () {
          if (timeout) { clearTimeout(timeout); }
          timeout = setTimeout(fn.apply.bind(fn, this, arguments), delay);
        };
      }

      var yas_getPasswordStrengthDeb = yas_debounce(200, yas_getPasswordStrength);

      function yas_onPasswordChange(e) {
        if (Boolean(e.target.value) && e.target.value.length < #{toJSON maxPasswordLength}) {
            yas_getPasswordStrengthDeb(e.target.value);
        } else if (!Boolean(e.target.value)) {
          yas_updateFeedback("", #{toJSON blankPasswordScore});
        }
      }

      document.getElementById("password").addEventListener("input", yas_onPasswordChange);
    |]

setPasswordTemplateDef :: forall a. YesodAuthSimple a => (AuthRoute -> Route a) -> Route a -> Maybe Text -> WidgetFor a ()
setPasswordTemplateDef toParent url mErr =
  let pwField = passwordFieldTemplate @a toParent in
    [whamlet|
      $newline never
      $maybe err <- mErr
        <div class="alert">#{err}

      <h1>Set new password
      <form method="post" action="@{url}">
        ^{pwField}
        <button type="submit">Save
    |]

invalidTokenTemplateDef :: Text -> WidgetFor a ()
invalidTokenTemplateDef msg = [whamlet|
  $newline never
  <.invalid-token>
    <h1>Invalid key
    <p>#{msg}
|]

userExistsTemplateDef :: WidgetFor a ()
userExistsTemplateDef = [whamlet|
  $newline never
  <.user-exists>
    <h1>Failed to create account
    <p>User already exists
|]

registerSuccessTemplateDef :: WidgetFor a ()
registerSuccessTemplateDef = [whamlet|
  $newline never
  <.register-success>
    <h1>Account created!
|]

resetPasswordEmailSentTemplateDef :: WidgetFor a ()
resetPasswordEmailSentTemplateDef = [whamlet|
  $newline never
  <.password-reset-email-sent>
    <h1>Email Sent!
    <p>An email has been sent to your address.
    <p>Click on the link in the email to complete the password reset.
|]

confirmationEmailSentTemplateDef :: WidgetFor a ()
confirmationEmailSentTemplateDef = [whamlet|
  $newline never
  <.confirmation-email-sent">
    <h1>Email sent
    <p>
      A confirmation email has been sent to your address.
      Click on the link in the email to complete the registration.
|]

confirmTempateDef :: forall a. YesodAuthSimple a => (AuthRoute -> Route a) -> Route a -> Email -> Maybe Text -> WidgetFor a ()
confirmTempateDef toParent confirmUrl (Email email) mErr =
  let pwField = passwordFieldTemplate @a toParent in
  [whamlet|
    $newline never
    $maybe err <- mErr
      <div class="alert">#{err}

    <.confirm>
      <h1>Set Your Password
      <form method="post" action="@{confirmUrl}">
        <p>#{email}
        ^{pwField}
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
        <input#email
          type="email"
          name="email"
          placeholder="Enter your email address"
          autofocus
          required>
      <button type="submit">Register
      <p>Already have an account? <a href="@{toParent loginR}">Sign in</a>.
|]
