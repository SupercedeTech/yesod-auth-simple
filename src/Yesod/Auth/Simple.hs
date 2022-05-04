{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

{- | A Yesod plugin for traditional email/password authentication

 This plugin uses an alternative flow to Yesod.Auth.Email fom the yesod-auth
 package.

__Note:__ this plugin reserves the following session names for its needs:

 * @yesod-auth-simple-error@
 * @yesod-auth-simple-email@
 * @yas-set-password-token@
 * @yas-registration-token@
 * @yas-password-backup@
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
  , confirmTemplateDef
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
    -- * Error handlers
  , getError
  , setError
  , cleanError
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

import ClassyPrelude
import Crypto.Hash (Digest, SHA256)
import qualified Crypto.Hash as C
import Crypto.Random (getRandomBytes)
import Crypto.Scrypt (EncryptedPass(..), Pass(..), encryptPassIO', verifyPass')
import Data.Aeson
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64Url
import Data.Function ((&))
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8', decodeUtf8With)
import Data.Text.Encoding.Error (lenientDecode)
import qualified Data.Vector as Vec
import Network.HTTP.Types (badRequest400, tooManyRequests429)
import Network.Wai (responseBuilder)
import Text.Blaze.Html.Renderer.Utf8 (renderHtmlBuilder)
import Text.Email.Validate (canonicalizeEmail)
import Text.Hamlet (hamletFile)
import Text.Julius (juliusFile)
import Text.Lucius (luciusFile)
import qualified Text.Password.Strength as PW
import qualified Text.Password.Strength.Config as PW
import Yesod.Auth
import Yesod.Auth.Simple.Types
import Yesod.Core
import Yesod.Core.Json as J
import Yesod.Form (iopt, ireq, runInputPost, textField)

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

confirmationEmailResentR :: AuthRoute
confirmationEmailResentR = PluginR "simple" ["confirmation-email-resent"]

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
  -- | Alias for some UserId datatype, likely same as the one in YesodAuth
  -- Refer to documentation for yesod-auth: http://hackage.haskell.org/package/yesod-auth
  type AuthSimpleId a

  -- | route to redirect to after resetting password e.g. homepage
  afterPasswordRoute :: a -> Route a

  -- | find user by email e.g. `runDB $ getBy $ UniqueUser email`
  getUserId :: Email -> AuthHandler a (Maybe (AuthSimpleId a))

  -- | find user's password (encrypted), handling user not found case
  getUserPassword :: AuthSimpleId a -> AuthHandler a EncryptedPass

  -- | return this content after successful user registration
  onRegisterSuccess :: AuthHandler a TypedContent

  -- | insert user to database with just email and password
  -- other mandatory fields are not supported
  insertUser :: Email -> EncryptedPass -> AuthHandler a (Maybe (AuthSimpleId a))

  -- | update record in database after validation
  updateUserPassword :: AuthSimpleId a -> EncryptedPass -> AuthHandler a ()

  -- | Return time until which the user should not be allowed to log in.
  -- The time is returned so that the UI can provide a helpful message in the
  -- event that a legitimate user somehow triggers the rate-limiting mechanism.
  -- If the time is Nothing, the user may log in.
  shouldPreventLoginAttempt ::
    Maybe (AuthSimpleId a) -> AuthHandler a (Maybe UTCTime)
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

  {- | Сheck if a registration confirmation is pending for the given email.
    
    @since 1.0.0
  -}
  isConfirmationPending :: Email -> AuthHandler a Bool
  isConfirmationPending _ = pure False

  -- | Like 'matchRegistrationToken' but for password resets.
  matchPasswordToken :: Text -> AuthHandler a (Maybe (AuthSimpleId a))

  -- | Can be used to invalidate the registration token. This is
  -- different from 'onRegisterSuccess' because this will also be
  -- called for existing users who use the registration form as a
  -- one-time login link. Note that 'onPasswordUpdated' can handle the
  -- case where a password reset token is used.
  onRegistrationTokenUsed :: Email -> AuthHandler a ()
  onRegistrationTokenUsed _ = pure ()
  
  {- | What to do if the email specified during registration is already registered.
    
    @since 1.0.0
  -}
  onEmailAlreadyExist :: AuthHandler a TypedContent
  onEmailAlreadyExist = do
    let msg = "This email address is already in use. Please login to your existing account."
    redirectWithError registerR msg

  -- | Password field widget for a chosen PasswordCheck algorithm
  passwordFieldTemplate :: (AuthRoute -> Route a) -> WidgetFor a ()
  passwordFieldTemplate tp =
    case passwordCheck @a of
      Zxcvbn minStren extraWords' ->
        passwordFieldTemplateZxcvbn tp minStren extraWords'
      RuleBased _ -> passwordFieldTemplateBasic

  -- | A template for showing the user authentication form
  --
  -- While a default is provided, you should probably override this with a
  -- template that matches your own product's branding.
  loginTemplate :: (AuthRoute -> Route a)
    -> Maybe Text  -- ^ Error
    -> Maybe Text  -- ^ Email
    -> WidgetFor a ()
  loginTemplate = loginTemplateDef

  registerTemplate :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
  registerTemplate = registerTemplateDef

  resetPasswordTemplate ::
       (AuthRoute -> Route a)
    -> Maybe Text
    -> WidgetFor a ()
  resetPasswordTemplate = resetPasswordTemplateDef

  confirmTemplate ::
       (AuthRoute -> Route a)
    -> Route a
    -> Email
    -> Maybe Text
    -> WidgetFor a ()
  confirmTemplate = confirmTemplateDef

  confirmationEmailSentTemplate :: WidgetFor a ()
  confirmationEmailSentTemplate = confirmationEmailSentTemplateDef

  {- | Template to notify user that a confirmation email has been resent.

    @since 1.0.0
  -}
  confirmationEmailResentTemplate :: WidgetFor a ()
  confirmationEmailResentTemplate = confirmationEmailSentTemplate

  resetPasswordEmailSentTemplate :: WidgetFor a ()
  resetPasswordEmailSentTemplate = resetPasswordEmailSentTemplateDef

  registerSuccessTemplate :: WidgetFor a ()
  registerSuccessTemplate = registerSuccessTemplateDef

  userExistsTemplate :: WidgetFor a ()
  userExistsTemplate = userExistsTemplateDef

  invalidPasswordTokenTemplate :: Text -> WidgetFor a ()
  invalidPasswordTokenTemplate = invalidTokenTemplateDef

  invalidRegistrationTokenTemplate :: Text -> WidgetFor a ()
  invalidRegistrationTokenTemplate = invalidTokenTemplateDef

  tooManyLoginAttemptsTemplate :: UTCTime -> WidgetFor a ()
  tooManyLoginAttemptsTemplate = tooManyLoginAttemptsTemplateDef

  setPasswordTemplate ::
       (AuthRoute -> Route a)
    -> Route a
    -> Maybe Text
    -> WidgetFor a ()
  setPasswordTemplate = setPasswordTemplateDef

  -- | Run after a user successfully changing the user's
  -- password. This is a good time to delete any password reset tokens
  -- for this user.
  onPasswordUpdated :: AuthSimpleId a -> AuthHandler a ()
  onPasswordUpdated _ = setMessage "Password has been updated"

  -- | Action called when a bot is detected
  onBotPost :: AuthHandler a ()
  onBotPost = pure ()

  -- | Provide suitable constructor e.g. `RuleBased 8`
  passwordCheck :: PasswordCheck
  passwordCheck = Zxcvbn PW.Safe Vec.empty

-- | This instance of AuthPlugin for inserting into `authPlugins` of YesodAuth
authSimple :: YesodAuthSimple m => AuthPlugin m
authSimple = AuthPlugin "simple" dispatch loginHandlerRedirect

loginHandlerRedirect :: (Route Auth -> Route a) -> WidgetFor a ()
loginHandlerRedirect tm = redirectTemplate $ tm loginR

dispatch :: YesodAuthSimple a => Text -> [Text] -> AuthHandler a TypedContent
dispatch method path = case (method, path) of
  ("GET",  ["register"])                  -> sr getRegisterR
  ("POST", ["register"])                  -> sr postRegisterR
  ("GET",  ["confirm", token])            -> sr $ getConfirmTokenR token
  ("GET",  ["confirm"])                   -> sr getConfirmR
  ("POST", ["confirm"])                   -> sr postConfirmR
  ("GET",  ["confirmation-email-sent"])   -> sr getConfirmationEmailSentR
  -- @since 1.0.0
  ("GET",  ["confirmation-email-resent"]) -> sr getConfirmationEmailResentR
  ("GET",  ["register-success"])          -> sr getRegisterSuccessR
  ("GET",  ["user-exists"])               -> sr getUserExistsR
  ("GET",  ["login"])                     -> sr getLoginR
  ("POST", ["login"])                     -> sr postLoginR
  ("GET",  ["set-password", token])       -> sr $ getSetPasswordTokenR token
  ("GET",  ["set-password"])              -> sr getSetPasswordR
  ("POST", ["set-password"])              -> sr postSetPasswordR
  ("GET",  ["reset-password"])            -> sr getResetPasswordR
  ("POST", ["reset-password"])            -> sr postResetPasswordR
  ("GET",  ["reset-password-email-sent"]) -> sr getResetPasswordEmailSentR
  -- NB: We use a POST instead of GET so that we don't send the password
  -- in the URL query string
  ("POST", ["password-strength"])         -> sr postPasswordStrengthR
  _                                       -> notFound
  where sr r = r >>= sendResponse

-- | Registration page
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

-- | Reset password page
getResetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
getResetPasswordR = do
  mErr <- getError
  tp   <- getRouteToParent
  selectRep . provideRep . authLayout $ do
    setTitle "Reset password"
    resetPasswordTemplate tp mErr

-- | Login page
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

-- | Name for a password-reset token to store in cookies
-- see getSetPasswordTokenR for motivation
-- `yas` is short for Yesod Auth Simple :)
passwordTokenSessionKey :: Text
passwordTokenSessionKey = "yas-set-password-token"

-- | Another key for registration tokens
registrationTokenSessionKey :: Text
registrationTokenSessionKey = "yas-registration-token"

genToken :: IO ByteString
genToken = getRandomBytes 24

-- | Hashes input via SHA256 and returns the hash encoded as base64 text
hashAndEncodeToken :: ByteString -> Text
hashAndEncodeToken bs = decodeUtf8 . B64.encode
               $ ByteArray.convert (C.hash bs :: Digest SHA256)

-- | encode to base64url form
encodeToken :: ByteString -> Text
encodeToken = decodeUtf8With lenientDecode . B64Url.encode

-- | Decode from base64url. Lenient decoding because this is random
-- input from the user and not all valid utf8 is valid base64
decodeToken :: Text -> ByteString
decodeToken = B64Url.decodeLenient . encodeUtf8

-- | Lookup and verify registration token
verifyRegisterTokenFromSession :: YesodAuthSimple a
  => AuthHandler a (Maybe Email)
verifyRegisterTokenFromSession =
  maybe (pure Nothing) matchRegistrationToken
    =<< lookupSession registrationTokenSessionKey

-- | Lookup and verify password token
verifyPasswordTokenFromSession :: YesodAuthSimple a
                               => AuthHandler a (Maybe (AuthSimpleId a))
verifyPasswordTokenFromSession =
  maybe (pure Nothing) matchPasswordToken
    =<< lookupSession passwordTokenSessionKey

-- | Delete registration token from cookie and maybe callback
markRegisterTokenAsUsed :: YesodAuthSimple a => Maybe Email -> AuthHandler a ()
markRegisterTokenAsUsed mEmail = do
  deleteSession registrationTokenSessionKey
  case mEmail of
    Just email -> onRegistrationTokenUsed email
    _          -> pure ()

-- | Accept registration form and send a verification link
postRegisterR :: YesodAuthSimple a => AuthHandler a TypedContent
postRegisterR = do
  clearError
  (honeypot, email) <- runInputPost $ (,)
                      <$> iopt textField honeypotName
                      <*> ireq textField "email"
  mEmail <- fmap Email <$> validateAndNormalizeEmail email
  case mEmail of
    _ | isJust honeypot -> do
          onBotPost
          let msg = "An unexpected error occurred.\
                    \ Please try again or contact support\
                    \ if the problem persists."
          redirectWithError registerR msg
    Just email' -> do
      getUserId email' >>= \case
        -- User with that email already exists
        Just _  -> onEmailAlreadyExist
        Nothing -> do
          tp <- getRouteToParent
          renderUrl <- getUrlRender
          rawToken <- liftIO genToken
          let url = renderUrl . tp . confirmTokenR $ encodeToken rawToken
              hashed = hashAndEncodeToken rawToken
          route <- bool confirmationEmailSentR confirmationEmailResentR
                    <$> isConfirmationPending email'
          sendVerifyEmail email' url hashed
          redirect $ tp route
    Nothing -> do
      setError "Invalid email address"
      tp <- getRouteToParent
      redirect $ tp registerR

-- | Accept email and send a password reset link
postResetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
postResetPasswordR = do
  clearError
  ur    <- getUrlRender
  token <- liftIO genToken
  email <- runInputPost $ ireq textField "email"
  tp    <- getRouteToParent
  let url = ur . tp . setPasswordTokenR $ encodeToken token
      hashed = hashAndEncodeToken token
  sendResetPasswordEmail (Email email) url hashed
  redirect $ tp resetPasswordEmailSentR

-- | Target URL reached from account confirmation email
-- Move the token into a session cookie and redirect to the
-- token-less URL (in order to avoid referrer leakage). The
-- alternative is to invalidate the token immediately and embed a
-- new one in the html form, but this has worse UX
getConfirmTokenR :: Text -> AuthHandler a TypedContent
getConfirmTokenR token = do
  setSession registrationTokenSessionKey . hashAndEncodeToken . decodeToken $ token
  tp <- getRouteToParent
  redirect $ tp confirmR

-- | Validate registration token and present confirmation screen to continue
-- e.g. include form to set password
getConfirmR :: YesodAuthSimple a => AuthHandler a TypedContent
getConfirmR = do
  mEmail <- verifyRegisterTokenFromSession
  case mEmail of
    Nothing -> do
      markRegisterTokenAsUsed Nothing
      invalidRegistrationTokenHandler
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

-- | Response and perhaps explanation for invalid or expired password token
invalidPasswordTokenHandler :: YesodAuthSimple a => AuthHandler a TypedContent
invalidPasswordTokenHandler = do
  html <- authLayout $ do
    setTitle "Invalid token"
    invalidPasswordTokenTemplate invalidPasswordTokenMessage
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder badRequest400 contentType
    & sendWaiResponse

-- | Response and perhaps explanation for invalid or expired registration token
invalidRegistrationTokenHandler :: YesodAuthSimple a => AuthHandler a TypedContent
invalidRegistrationTokenHandler = do
  html <- authLayout $ do
    setTitle "Invalid token"
    invalidRegistrationTokenTemplate invalidRegistrationMessage
  let contentType = [("Content-Type", "text/html")]
  renderHtmlBuilder html
    & responseBuilder badRequest400 contentType
    & sendWaiResponse

-- | Next step after email verification, usually to set password
confirmHandler ::
     YesodAuthSimple a
  => Route a
  -> Email
  -> AuthHandler a TypedContent
confirmHandler registerUrl email = do
  mErr <- getError
  tp <- getRouteToParent
  selectRep . provideRep . authLayout $ do
    setTitle "Confirm account"
    confirmTemplate tp registerUrl email mErr

-- | Check registration token again, take password and try to create user
postConfirmR :: YesodAuthSimple a => AuthHandler a TypedContent
postConfirmR = do
  clearError
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  mEmail <- verifyRegisterTokenFromSession
  case mEmail of
    _ | not okCsrf -> redirectWithError confirmR invalidCsrfMessage
    Nothing -> invalidRegistrationTokenHandler
    Just email -> do
      password <- runInputPost $ ireq textField "password"
      createUser email (Pass . encodeUtf8 $ password)

-- | Create user with valid password and return success page (or redirect)
createUser :: forall m. YesodAuthSimple m
           => Email -> Pass -> AuthHandler m TypedContent
createUser email password = do
  check <- liftIO $ strengthToEither
          <$> checkPasswordStrength (passwordCheck @m) password
  case check of
    Left msg -> do
      setError msg
      tp <- getRouteToParent
      redirect $ tp confirmR
    Right _ -> do
      markRegisterTokenAsUsed $ Just email
      encrypted <- liftIO $ encryptPassIO' password
      insertUser email encrypted >>= \case
        Just uid -> do
          let creds = Creds "simple" (toPathPiece uid) []
          setCreds False creds
          onRegisterSuccess
        Nothing -> do
          tp <- getRouteToParent
          redirect $ tp userExistsR

-- | Confirmation to show after sending verification email
getConfirmationEmailSentR :: YesodAuthSimple a => AuthHandler a TypedContent
getConfirmationEmailSentR = selectRep . provideRep . authLayout $ do
  setTitle "Confirmation email sent"
  confirmationEmailSentTemplate

{- | Confirmation to show after resending verification email.

  @since 1.0.0
-}
getConfirmationEmailResentR :: YesodAuthSimple a => AuthHandler a TypedContent
getConfirmationEmailResentR = selectRep . provideRep . authLayout $ do
  setTitle "Confirmation email resent"
  confirmationEmailResentTemplate

-- | Confirmation to show after sending password reset email
getResetPasswordEmailSentR :: YesodAuthSimple a => AuthHandler a TypedContent
getResetPasswordEmailSentR = selectRep . provideRep . authLayout $ do
  setTitle "Reset password email sent"
  resetPasswordEmailSentTemplate

-- | Another option for responding on successful registration
getRegisterSuccessR :: AuthHandler a TypedContent
getRegisterSuccessR = do
  setMessage "Account created. Welcome!"
  redirect ("/" :: Text)

-- | Redirected to when `insertUser` does not return UserID
getUserExistsR :: YesodAuthSimple a => AuthHandler a TypedContent
getUserExistsR = selectRep . provideRep . authLayout $ do
  setTitle "User already exists"
  userExistsTemplate

-- | JSON endpoint for validating password
postPasswordStrengthR :: forall a. (YesodAuthSimple a) => AuthHandler a J.Value
postPasswordStrengthR = do
  okCsrf <- hasValidCsrfParamNamed defaultCsrfParamName
  if not okCsrf
    then pure . toJSON $ BadPassword PW.Risky $ Just invalidCsrfMessage
    else do
      password <- runInputPost (ireq textField "password")
      let pass = Pass . encodeUtf8 $ password
      liftIO $ toJSON <$> checkPasswordStrength (passwordCheck @a) pass

-- | Validate password for given parameters with Zxcvbn library
checkPassWithZxcvbn ::
     PW.Strength
  -> Vector Text
  -> Day
  -> Text
  -> PasswordStrength
checkPassWithZxcvbn minStrength' extraWords' day password =
  let conf = PW.addCustomFrequencyList extraWords' PW.en_US
      guesses = PW.score conf day password
      stren = PW.strength guesses
  in if stren >= minStrength' then GoodPassword stren
     else BadPassword stren $ Just "The password is not strong enough"

-- | Validate password with simple length rule
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

-- | Explain password strength with a given validator
checkPasswordStrength :: PasswordCheck -> Pass -> IO PasswordStrength
checkPasswordStrength check pass =
  case decodeUtf8' (getPass pass) of
    Left _ -> pure $ BadPassword PW.Weak $ Just "Invalid characters in password"
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

-- | Accept login form, check attempts limit and authenticate or redirect user
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

tooManyLoginAttemptsHandler ::
     YesodAuthSimple a
  => UTCTime
  -> AuthHandler a TypedContent
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
invalidCsrfMessage =
  "Invalid anti-forgery token. \
  \Please try again in a new browser tab or window. \
  \Contact support if the problem persists."

invalidRegistrationMessage :: Text
invalidRegistrationMessage =
  "Invalid registration link. \
  \Please try registering again and contact support if the problem persists"

invalidPasswordTokenMessage :: Text
invalidPasswordTokenMessage =
  "Invalid password reset token. \
  \Please try again and contact support if the problem persists."

-- | Target URL reached from password reset email
-- Move the token into a session cookie and redirect to the
-- token-less URL (in order to avoid referrer leakage). The
-- alternative is to invalidate the token immediately and embed a
-- new one in the html form, but this has worse UX
getSetPasswordTokenR :: Text -> AuthHandler a TypedContent
getSetPasswordTokenR token = do
  setSession passwordTokenSessionKey . hashAndEncodeToken . decodeToken $ token
  tp <- getRouteToParent
  redirect $ tp setPasswordR

-- | Validate password token and prompt for new password
getSetPasswordR :: YesodAuthSimple a => AuthHandler a TypedContent
getSetPasswordR = do
  mUid <- verifyPasswordTokenFromSession
  case mUid of
    Nothing -> invalidPasswordTokenHandler
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
    _ | not okCsrf -> redirectWithError setPasswordR invalidCsrfMessage
    Nothing -> do
      deleteSession passwordTokenSessionKey
      invalidPasswordTokenHandler
    Just uid -> do
      password <- runInputPost $ ireq textField "password"
      setPass uid (Pass . encodeUtf8 $ password)

-- | Check and update password, callback, then redirect to user page
setPass :: forall a. YesodAuthSimple a
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
  toWidget $(whamletFile "templates/redirect.hamlet")
  toWidget [julius|window.location = "@{destUrl}";|]

csrfTokenTemplate :: WidgetFor a ()
csrfTokenTemplate = do
  request <- getRequest
  $(whamletFile "templates/csrf-token.hamlet")

loginTemplateDef ::
     (AuthRoute -> Route a)
  -> Maybe Text
  -> Maybe Text
  -> WidgetFor a ()
loginTemplateDef toParent mErr mEmail = $(whamletFile "templates/login.hamlet")

passwordFieldTemplateBasic :: WidgetFor a ()
passwordFieldTemplateBasic =
  $(whamletFile "templates/password-field-basic.hamlet")

zxcvbnJsUrl :: Text
zxcvbnJsUrl = "https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js"

passwordFieldTemplateZxcvbn ::
     (AuthRoute -> Route a)
  -> PW.Strength
  -> Vector Text
  -> WidgetFor a ()
passwordFieldTemplateZxcvbn toParent minStren extraWords' = do
  let extraWordsStr = T.unwords . toList $ extraWords'
      blankPasswordScore = BadPassword PW.Risky Nothing
  mCsrfToken <- reqToken <$> getRequest
  addScriptRemote zxcvbnJsUrl
  toWidget $(hamletFile "templates/password-field-zxcvbn.hamlet")
  toWidget $(luciusFile "templates/password-field-zxcvbn.lucius")
  toWidget $(juliusFile "templates/password-field-zxcvbn.julius")

setPasswordTemplateDef ::
     forall a. YesodAuthSimple a
  => (AuthRoute -> Route a)
  -> Route a
  -> Maybe Text
  -> WidgetFor a ()
setPasswordTemplateDef toParent url mErr =
  let pwField = passwordFieldTemplate @a toParent
   in $(whamletFile "templates/set-password.hamlet")

invalidTokenTemplateDef :: Text -> WidgetFor a ()
invalidTokenTemplateDef msg = $(whamletFile "templates/invalid-token.hamlet")

tooManyLoginAttemptsTemplateDef :: UTCTime -> WidgetFor a ()
tooManyLoginAttemptsTemplateDef expires =
  let formatted = formatTime defaultTimeLocale "%d/%m/%_Y %T" expires
   in $(whamletFile "templates/too-many-login-attempts.hamlet")

userExistsTemplateDef :: WidgetFor a ()
userExistsTemplateDef = $(whamletFile "templates/user-exists.hamlet")

registerSuccessTemplateDef :: WidgetFor a ()
registerSuccessTemplateDef = $(whamletFile "templates/register-success.hamlet")

resetPasswordEmailSentTemplateDef :: WidgetFor a ()
resetPasswordEmailSentTemplateDef =
  $(whamletFile "templates/reset-password-email-sent.hamlet")

confirmationEmailSentTemplateDef :: WidgetFor a ()
confirmationEmailSentTemplateDef =
  $(whamletFile "templates/confirmation-email-sent.hamlet")

confirmTemplateDef ::
     forall a. YesodAuthSimple a
  => (AuthRoute -> Route a)
  -> Route a
  -> Email
  -> Maybe Text
  -> WidgetFor a ()
confirmTemplateDef toParent confirmUrl (Email email) mErr =
  let pwField = passwordFieldTemplate @a toParent
   in $(whamletFile "templates/confirm.hamlet")

resetPasswordTemplateDef ::
     (AuthRoute -> Route a)
  -> Maybe Text
  -> WidgetFor a ()
resetPasswordTemplateDef toParent mErr =
  $(whamletFile "templates/reset-password.hamlet")

honeypotName :: Text
honeypotName = "yas-password-backup"

honeypotFieldTemplate :: WidgetFor a ()
honeypotFieldTemplate = do
  toWidget [lucius| .#{honeypotName} { display:none !important; } |]
  toWidget $(hamletFile "templates/honeypot-field.hamlet")

registerTemplateDef :: (AuthRoute -> Route a) -> Maybe Text -> WidgetFor a ()
registerTemplateDef toParent mErr = $(whamletFile "templates/register.hamlet")
