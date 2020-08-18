{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE Rank2Types          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}

{- | A Yesod plugin for traditional email/password authentication

 This plugin uses an alternative flow to Yesod.Auth.Email fom the yesod-auth
 package.

__Note:__ this plugin reserves the following session names for its needs:

 * @yesod-auth-simple-error@
 * @yesod-auth-simple-email@
-}

module Yesod.Auth.Simple
  ( -- * Plugin
    YesodAuthSimple(..)
  , authSimple
    -- * Routes
  , loginR
  , registerR
  , resetPasswordR
  , resetPasswordEmailSentR
  , setPasswordTokenR
  , confirmTokenR
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
  , honeypotFieldTemplate
    -- * Tokens
  , genToken
  , encodeToken
  , hashAndEncodeToken
  , decodeToken
    -- * Misc
  , maxPasswordLength
    -- * Types
  , Email(..)
  , Password(..)
  , PW.Strength(..)
  , PasswordCheck(..)
  , PasswordStrength(..)
    -- * Re-export from Scrypt
  , EncryptedPass(..)
  , Pass(..)
  , encryptPassIO'
  ) where

import           ClassyPrelude
import           Crypto.Hash                   (Digest, SHA256)
import qualified Crypto.Hash                   as C
import           Crypto.Random                 (getRandomBytes)
import           Crypto.Scrypt                 (EncryptedPass (..), Pass (..),
                                                encryptPassIO', verifyPass')
import           Data.Aeson
import qualified Data.ByteArray                as ByteArray
import           Data.ByteString               (ByteString)
import qualified Data.ByteString.Base64        as B64
import qualified Data.ByteString.Base64.URL    as B64Url
import           Data.Function                 ((&))
import           Data.Text                     (Text)
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8', decodeUtf8With)
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.Time                     (Day, UTCTime (..),
                                                getCurrentTime)
import           Data.Vector                   (Vector)
import qualified Data.Vector                   as Vec
import           Network.HTTP.Types            (badRequest400,
                                                tooManyRequests429)
import           Network.Wai                   (responseBuilder)
import           Text.Blaze.Html.Renderer.Utf8 (renderHtmlBuilder)
import           Text.Email.Validate           (canonicalizeEmail)
import qualified Text.Password.Strength        as PW
import qualified Text.Password.Strength.Config as PW
import           Yesod.Auth
import           Yesod.Auth.Simple.Types
import           Yesod.Core
import           Yesod.Core.Json               as J
import           Yesod.Form                    (iopt, ireq, runInputPost,
                                                textField)

minPasswordLength :: Int
minPasswordLength = 8 -- min length required in NIST SP 800-63B

maxPasswordLength :: Int
maxPasswordLength = 150 -- zxcvbn takes too long after this point

confirmTokenR :: Text -> AuthRoute
confirmTokenR token = PluginR "simple" ["confirm", token]

confirmR :: AuthRoute
confirmR = PluginR "simple" ["confirm"]

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

  onRegisterSuccess :: AuthHandler a TypedContent

  insertUser :: Email -> EncryptedPass -> AuthHandler a (Maybe (AuthSimpleId a))

  updateUserPassword :: AuthSimpleId a -> EncryptedPass -> AuthHandler a ()

  shouldPreventLoginAttempt :: Maybe (AuthSimpleId a) -> AuthHandler a (Maybe UTCTime)
  shouldPreventLoginAttempt _ = pure Nothing

  -- | Perform an action on a login attempt.
  onLoginAttempt :: Maybe (AuthSimpleId a)
                 -- ^ The user id of the given email, if one exists
                 -> Bool
                 -- ^ Whether the password given was correct. Always
                 -- False when user id is Nothing
                 -> AuthHandler a ()
  onLoginAttempt _ _ = pure ()

  -- | Called when someone requests registration.
  sendVerifyEmail :: Email -- ^ A valid email they've registered.
                  -> VerUrl -- ^ An verification URL (in absolute form).
                  -> Text   -- ^ A sha256 base64-encoded hash of the
                           -- verification token. You should store this in your
                           -- database.
                  -> AuthHandler a ()
  sendVerifyEmail _ url _ = liftIO . print $ url

  -- | Like 'sendVerifyEmail' but for password resets.
  sendResetPasswordEmail :: Email -> VerUrl -> Text -> AuthHandler a ()
  sendResetPasswordEmail _ url _ = liftIO . print $ url

  -- | Given a hashed and base64-encoded token from the user, look up
  -- if the token is still valid and return the associated email if so.
  matchRegistrationToken :: Text -> AuthHandler a (Maybe Email)

  -- | Like 'matchRegistrationToken' but for password resets.
  matchPasswordToken :: Text -> AuthHandler a (Maybe (AuthSimpleId a))

  -- | Can be used to invalidate the registration token. This is
  -- different from 'onRegisterSuccess' because this will also be
  -- called for existing users who use the registration form as a
  -- one-time login link. Note that 'onPasswordUpdated' can handle the
  -- case where a password reset token is used.
  onRegistrationTokenUsed :: Email -> AuthHandler a ()
  onRegistrationTokenUsed _ = pure ()

  passwordFieldTemplate :: (AuthRoute -> Route a) -> WidgetFor a ()
  passwordFieldTemplate tp =
    case passwordCheck @a of
      Zxcvbn minStren extraWords' -> passwordFieldTemplateZxcvbn tp minStren extraWords'
      RuleBased _ -> passwordFieldTemplateBasic

  loginTemplate
    :: (AuthRoute -> Route a)
    -> Maybe Text  -- ^ Error
    -> Maybe Text  -- ^ Email
    -> WidgetFor a ()
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

  tooManyLoginAttemptsTemplate :: UTCTime -> WidgetFor a ()
  tooManyLoginAttemptsTemplate = tooManyLoginAttemptsTemplateDef

  setPasswordTemplate :: (AuthRoute -> Route a) -> Route a -> Maybe Text -> WidgetFor a ()
  setPasswordTemplate = setPasswordTemplateDef

  -- | Run after a user successfully changing the user's
  -- password. This is a good time to delete any password reset tokens
  -- for this user.
  onPasswordUpdated :: AuthSimpleId a -> AuthHandler a ()
  onPasswordUpdated _ = setMessage "Password has been updated"

  onBotPost :: AuthHandler a ()
  onBotPost = pure ()

  passwordCheck :: PasswordCheck
  passwordCheck = Zxcvbn PW.Safe Vec.empty

authSimple :: YesodAuthSimple m => AuthPlugin m
authSimple = AuthPlugin "simple" dispatch loginHandlerRedirect

loginHandlerRedirect :: (Route Auth -> Route a) -> WidgetFor a ()
loginHandlerRedirect tm = redirectTemplate $ tm loginR

dispatch :: YesodAuthSimple a => Text -> [Text] -> AuthHandler a TypedContent
dispatch "GET"  ["register"] = getRegisterR >>= sendResponse
dispatch "POST" ["register"] = postRegisterR >>= sendResponse
dispatch "GET"  ["confirm", token] = getConfirmTokenR token >>= sendResponse
dispatch "GET"  ["confirm"] = getConfirmR >>= sendResponse
dispatch "POST" ["confirm"] = postConfirmR >>= sendResponse
dispatch "GET"  ["confirmation-email-sent"] = getConfirmationEmailSentR >>= sendResponse
dispatch "GET"  ["register-success"] = getRegisterSuccessR >>= sendResponse
dispatch "GET"  ["user-exists"] = getUserExistsR >>= sendResponse
dispatch "GET"  ["login"] = getLoginR >>= sendResponse
dispatch "POST" ["login"] = postLoginR >>= sendResponse
dispatch "GET"  ["set-password", token] = getSetPasswordTokenR token >>= sendResponse
dispatch "GET"  ["set-password"] = getSetPasswordR >>= sendResponse
dispatch "POST" ["set-password"] = postSetPasswordR >>= sendResponse
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
  mEmail <- getEmail
  muid <- maybeAuthId
  tp   <- getRouteToParent
  case muid of
    Nothing -> selectRep . provideRep . authLayout $ do
      setTitle "Login"
      loginTemplate tp mErr mEmail
    Just _ -> redirect $ toPathPiece ("/" :: String)

passwordTokenSessionKey :: Text
passwordTokenSessionKey = "yas_set_password_token"

genToken :: IO ByteString
genToken = getRandomBytes 24

-- | Hashes input via SHA256 and returns the hash encoded as base64 text
hashAndEncodeToken :: ByteString -> Text
hashAndEncodeToken bs = decodeUtf8 . B64.encode
               $ ByteArray.convert (C.hash bs :: Digest SHA256)

-- encode to base64url form
encodeToken :: ByteString -> Text
encodeToken = decodeUtf8With lenientDecode . B64Url.encode

-- Decode from base64url. Lenient decoding because this is random
-- input from the user and not all valid utf8 is valid base64
decodeToken :: Text -> ByteString
decodeToken = B64Url.decodeLenient . encodeUtf8

verifyRegisterTokenFromSession :: YesodAuthSimple a
                               => AuthHandler a (Maybe Email)
verifyRegisterTokenFromSession = do
  maybe (pure Nothing) matchRegistrationToken
    =<< lookupSession passwordTokenSessionKey

verifyPasswordTokenFromSession :: YesodAuthSimple a
                               => AuthHandler a (Maybe (AuthSimpleId a))
verifyPasswordTokenFromSession = do
  maybe (pure Nothing) matchPasswordToken
    =<< lookupSession passwordTokenSessionKey

markRegisterTokenAsUsed :: YesodAuthSimple a => Maybe Email -> AuthHandler a ()
markRegisterTokenAsUsed mEmail = do
  deleteSession passwordTokenSessionKey
  case mEmail of
    Just email -> onRegistrationTokenUsed email
    _          -> pure ()

postRegisterR :: YesodAuthSimple a => AuthHandler a TypedContent
postRegisterR = do
  clearError
  (honeypot, email) <- runInputPost $ (,)
                      <$> iopt textField honeypotName
                      <*> ireq textField "email"
  mEmail <- validateAndNormalizeEmail email
  case mEmail of
    _ | isJust honeypot -> do
          onBotPost
          invalidTokenHandler "An unexpected error occurred. Please try again or contact support if the problem persists"
    Just email' -> do
      tp <- getRouteToParent
      renderUrl <- getUrlRender
      rawToken <- liftIO genToken
      let url = renderUrl . tp . confirmTokenR $ encodeToken rawToken
          hashed = hashAndEncodeToken rawToken
      sendVerifyEmail (Email email') url hashed
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
  tp <- getRouteToParent
  case mUid of
    Just _ -> do
      renderUrl <- getUrlRender
      rawToken <- liftIO genToken
      let url = renderUrl . tp . setPasswordTokenR $ encodeToken rawToken
          hashed = hashAndEncodeToken rawToken
      sendResetPasswordEmail (Email email) url hashed
      redirect $ tp resetPasswordEmailSentR
    Nothing -> do
      redirect $ tp resetPasswordEmailSentR

getConfirmTokenR :: Text -> AuthHandler a TypedContent
getConfirmTokenR token = do
  setSession passwordTokenSessionKey . hashAndEncodeToken . decodeToken $ token
  tp <- getRouteToParent
  redirect $ tp confirmR

getConfirmR :: YesodAuthSimple a => AuthHandler a TypedContent
getConfirmR = do
  mEmail <- verifyRegisterTokenFromSession
  case mEmail of
    Nothing -> do
      markRegisterTokenAsUsed Nothing
      invalidTokenHandler invalidRegistrationMessage
    Just email ->
      -- If user already registered, redirect to homepage as
      -- authenticated user. Otherwise, keep the token in the cookie
      -- and redirect to the confirm handler, checking and deleting
      -- the token only after the user sets up their password.
      getUserId email >>= maybe (doConfirm email) (redirectToHome email)
  where
    redirectToHome email uid = do
      markRegisterTokenAsUsed $ Just email
      setCredsRedirect $ Creds "simple" (toPathPiece uid) []
    doConfirm email = do tp <- getRouteToParent
                         confirmHandler (tp confirmR) email

invalidTokenHandler :: YesodAuthSimple a => Text -> AuthHandler a TypedContent
invalidTokenHandler msg = do
  html <- authLayout $ do
    setTitle "Invalid key"
    invalidTokenTemplate msg
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder badRequest400 contentType
    & sendWaiResponse

confirmHandler :: YesodAuthSimple a => Route a -> Email -> AuthHandler a TypedContent
confirmHandler registerUrl email = do
  mErr <- getError
  tp <- getRouteToParent
  selectRep . provideRep . authLayout $ do
    setTitle "Confirm account"
    confirmTemplate tp registerUrl email mErr

postConfirmR :: YesodAuthSimple a => AuthHandler a TypedContent
postConfirmR = do
  clearError
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  mEmail <- verifyRegisterTokenFromSession
  case mEmail of
    _ | not okCsrf -> invalidTokenHandler invalidCsrfMessage
    Nothing -> invalidTokenHandler invalidTokenMessage
    Just email -> do
      password <- runInputPost $ ireq textField "password"
      createUser email (Pass . encodeUtf8 $ password)

createUser :: forall m. YesodAuthSimple m => Email -> Pass -> AuthHandler m TypedContent
createUser email password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @m) password
  case check of
    Left msg -> do
      setError msg
      tp <- getRouteToParent
      redirect $ tp $ confirmR
    Right _ -> do
      markRegisterTokenAsUsed $ Just email
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
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  if not okCsrf
    then pure . toJSON $ BadPassword PW.Risky $ Just invalidCsrfMessage
    else do
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

-- | Session name used for the errors.
errorSessionName :: Text
errorSessionName = "yesod-auth-simple-error"

-- | Session name used for the email storage.
emailSessionName :: Text
emailSessionName = "yesod-auth-simple-email"

{- | Get the error session (see 'errorSessionName') if present. It also clears
up the session after.
-}
getError :: AuthHandler a (Maybe Text)
getError = do
  mErr <- lookupSession errorSessionName
  clearError
  return mErr

-- | Sets up the error session ('errorSessionName') to the given value.
setError :: Text -> AuthHandler a ()
setError = setSession errorSessionName

-- | Clears up the error session ('errorSessionName').
clearError :: AuthHandler a ()
clearError = deleteSession errorSessionName

{- | Get the email session (see 'emailSessionName') if present. It also clears
up the session after.
-}
getEmail :: AuthHandler a (Maybe Text)
getEmail = do
  mEmail <- lookupSession emailSessionName
  clearEmail
  return mEmail

-- | Sets up the email session ('emailSessionName') to the given value.
setEmail :: Text -> AuthHandler a ()
setEmail = setSession emailSessionName

-- | Clears up the email session ('emailSessionName').
clearEmail :: AuthHandler a ()
clearEmail = deleteSession emailSessionName

postLoginR :: YesodAuthSimple a => AuthHandler a TypedContent
postLoginR = do
  clearError
  clearEmail
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  if not okCsrf
    then redirectWithError loginR invalidCsrfMessage
    else do
      (email, password') <- runInputPost $ (,)
        <$> ireq textField "email"
        <*> ireq textField "password"
      setEmail email
      let password = Pass . encodeUtf8 $ password'
      mUid <- getUserId (Email email)
      mLockedOut <- shouldPreventLoginAttempt mUid
      case (mLockedOut, mUid) of
        (Just expires, _) -> tooManyLoginAttemptsHandler expires
        (_, Just uid) -> do
          storedPassword <- getUserPassword uid
          if verifyPass' password storedPassword
            then do
              onLoginAttempt (Just uid) True
              setCredsRedirect $ Creds "simple" (toPathPiece uid) []
            else do
              onLoginAttempt (Just uid) False
              wrongEmailOrPasswordRedirect
        _ -> do
          onLoginAttempt Nothing False
          wrongEmailOrPasswordRedirect

tooManyLoginAttemptsHandler :: YesodAuthSimple a => UTCTime -> AuthHandler a TypedContent
tooManyLoginAttemptsHandler expires = do
  html <- authLayout $ do
    setTitle "Too many login attempts"
    tooManyLoginAttemptsTemplate expires
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder tooManyRequests429 contentType
    & sendWaiResponse

redirectTo :: AuthRoute -> AuthHandler a b
redirectTo route = do
  tp <- getRouteToParent
  redirect $ tp route

redirectWithError :: AuthRoute -> Text -> AuthHandler a TypedContent
redirectWithError route err = do
  setError err
  redirectTo route

wrongEmailOrPasswordRedirect :: AuthHandler a TypedContent
wrongEmailOrPasswordRedirect =
  redirectWithError loginR "Wrong email or password"

invalidCsrfMessage :: Text
invalidCsrfMessage = "Invalid anti-forgery token. Please try again in a new browser tab or window. Contact support if the problem persists"

invalidRegistrationMessage :: Text
invalidRegistrationMessage = "Invalid registration link. Please try registering again and contact support if the problem persists"

invalidTokenMessage :: Text
invalidTokenMessage = "Invalid password reset token. Please try again and contact support if the problem persists"

getSetPasswordTokenR :: Text -> AuthHandler a TypedContent
getSetPasswordTokenR token = do
  -- Move the token into a session cookie and redirect to the
  -- token-less URL (in order to avoid referrer leakage). The
  -- alternative is to invalidate the token immediately and embed a
  -- new one in the html form, but this has worse UX
  setSession passwordTokenSessionKey . hashAndEncodeToken . decodeToken $ token
  tp <- getRouteToParent
  redirect $ tp setPasswordR

getSetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
getSetPasswordR = do
  mUid <- verifyPasswordTokenFromSession
  case mUid of
    Nothing -> invalidTokenHandler invalidTokenMessage
    Just _ -> do
      tp <- getRouteToParent
      mErr <- getError
      selectRep . provideRep . authLayout $ do
        setTitle "Set password"
        setPasswordTemplate tp (tp setPasswordR) mErr

-- | Set a new password for the user
postSetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
postSetPasswordR = do
  clearError
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  mUid <- verifyPasswordTokenFromSession
  case mUid of
    _ | not okCsrf -> invalidTokenHandler invalidCsrfMessage
    Nothing -> do
      deleteSession passwordTokenSessionKey
      invalidTokenHandler invalidTokenMessage
    Just uid -> do
      password <- runInputPost $ ireq textField "password"
      setPass uid (Pass . encodeUtf8 $ password)

setPass
  :: forall a. YesodAuthSimple a
  => AuthSimpleId a
  -> Pass
  -> AuthHandler a TypedContent
setPass uid password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @a) password
  case check of
    Left msg -> do
      setError msg
      tp <- getRouteToParent
      redirect $ tp setPasswordR
    Right _ -> do
      encrypted <- liftIO $ encryptPassIO' password
      _         <- updateUserPassword uid encrypted
      onPasswordUpdated uid
      deleteSession passwordTokenSessionKey
      setCredsRedirect $ Creds "simple" (toPathPiece uid) []

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

csrfTokenTemplate :: WidgetFor a ()
csrfTokenTemplate = do
  request <- getRequest
  [whamlet|
    $newline never
    $maybe antiCsrfToken <- reqToken request
      <input type=hidden name=#{defaultCsrfParamName} value=#{antiCsrfToken}>
  |]

loginTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> Maybe Text -> WidgetFor a ()
loginTemplateDef toParent mErr mEmail = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <h1>Sign in
  <form method="post" action="@{toParent loginR}">
    ^{csrfTokenTemplate}
    <fieldset>
      <label for="email">Email
      $maybe email <- mEmail
        <input type="email" name="email" value=#{email} required>
      $nothing
        <input type="email" name="email" autofocus required>
    <fieldset>
      <label for="password">Password
      <input type="password" name="password" required :isJust mEmail:autofocus>
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
  mCsrfToken <- reqToken <$> getRequest
  let csrfToken = maybe "no-csrf-token" id mCsrfToken
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
        req.send(#{defaultCsrfParamName} + "=" + #{csrfToken}
                 + "&password=" + encodeURIComponent(password));
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
        ^{csrfTokenTemplate}
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

tooManyLoginAttemptsTemplateDef :: UTCTime -> WidgetFor a ()
tooManyLoginAttemptsTemplateDef expires = do
  let formatted = formatTime defaultTimeLocale "%d/%m/%_Y %T" expires
  [whamlet|
    $newline never
    <.too-many-attempts>
      <h1>Too many login attempts
      <p>You have been locked out from your account until #{formatted} GMT</p>
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
    <p>An email has been sent to your address provided that a corresponding user account exists in our system.
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
        ^{csrfTokenTemplate}
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

honeypotName :: Text
honeypotName = "yas--password-backup"

honeypotFieldTemplate :: WidgetFor a ()
honeypotFieldTemplate = do
  toWidget
    [lucius|
      .#{honeypotName} { display:none !important; }
    |]
  toWidget
    [hamlet|
      $newline never
      <fieldset class="#{honeypotName}">
        <label for="#{honeypotName}">
        <input type="text" name="#{honeypotName}" tabindex="none" autocomplete="off">
    |]

registerTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
registerTemplateDef toParent mErr = [whamlet|
  $newline never
  $maybe err <- mErr
    <div class="alert">#{err}

  <.register>
    <h1>Register new account
    <form method="post" action="@{toParent registerR}">
      ^{honeypotFieldTemplate}
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
