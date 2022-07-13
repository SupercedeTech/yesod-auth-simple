{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Yesod.Auth.SimpleSpec (spec) where

import qualified Data.Password.Scrypt as PSC
import qualified Data.Text as T
import TestImport

register :: Text -> YesodExample App ()
register email = request $ do
  setMethod "POST"
  setUrl $ AuthR registerR
  byLabelExact "Email" email

confirm :: Text -> YesodExample App ()
confirm password = request $ do
  addToken
  setMethod "POST"
  setUrl $ AuthR confirmR
  byLabelExact "Password" password

spec :: Spec
spec = withApp $ do

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
        register email
        followRedirect_
        statusIs 200
        bodyContains "Email sent"

    describe "with an invalid email address" $

      it "returns the user to the registration form with an error" $ do
        let email = "not_an_email"
        ur <- runHandler getUrlRender
        get $ AuthR registerR
        register email
        followRedirect >>=
          assertEq "path is registration form" (Right (ur (AuthR registerR)))

  describe "confirmation" $ do

    describe "with a weak password" $

      it "returns the user to the confirmation form with an error" $ do
        let email = "user@example.com"
        ur <- runHandler getUrlRender
        t <- runHandler . getTestToken $ Email email
        get $ AuthR $ confirmTokenR t
        followRedirect_
        -- NB: The following password would be fine without the
        -- commonDomainWords definition
        confirm "hello yesod 123"
        followRedirect >>=
          assertEq "path is confirmation form" (Right (ur (AuthR confirmR)))

    describe "with a password that is too long" $
      it "caps length at 150" $ do
        let email = "user@example.com"
            -- Not using a simple, eg, "a" replicate because that
            -- causes a bug hopefully soon fixed:
            -- github.com/sthenauth/zxcvbn-hs/issues/2
            password = T.replicate 12 "one two three" -- 156 chars
        ur <- runHandler getUrlRender
        t <- runHandler . getTestToken $ Email email
        get $ AuthR $ confirmTokenR t
        followRedirect_
        confirm password
        followRedirect >>=
          assertEq "path is confirmation form" (Right (ur (AuthR confirmR)))

    describe "with an adequately strong password" $

      it "inserts a new user" $ do
        let email = "user@example.com"
        ur <- runHandler getUrlRender
        get $ AuthR registerR
        register email
        token <- runHandler . getTestToken $ Email email
        get $ AuthR $ confirmTokenR token
        followRedirect_
        request $ do
          setMethod "POST"
          setUrl $ AuthR confirmR
          addToken_ "form"
          byLabelExact "Password" "really difficult yesod password here"
        followRedirect >>=
          assertNotEq "path is not confirmation form" (Right (ur (AuthR confirmR)))

    describe "with an invalid token" $

      it "renders the invalid token page" $ do
        let token = "not_a_valid_token"
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" "user@example.com"
        get $ AuthR $ confirmTokenR token
        followRedirect_
        statusIs 400

    describe "with an email that is not unique" $

      it "automatically authenticates the existing user" $ do
        encrypted <- liftIO $ PSC.hashPassword $ PSC.mkPassword "strongpass"
        let userEmail = Email  "user@example.com"
            userPassword = Password $ PSC.unPasswordHash $ encrypted
        runDB' . insert_ $ User{..}

        token <- runHandler $ getTestToken userEmail -- encryptRegisterToken userEmail
        get $ AuthR $ confirmTokenR token
        followRedirect_
        statusIs 303
        ur <- runHandler getUrlRender
        followRedirect >>= assertEq "redirection successful" (Right $ ur HomeR)

    describe "golden hashing test" $

      it "should match regardless of scrypt implementation" $ do
        -- This string is equivalent to "encryptPassIO' hello" from scrypt-0.5.0, which is what we
	-- were using previously. 
        let withScrypt = PSC.PasswordHash $ "14|8|1|+NCfU1Hyflh0D08VAGKtMCIRkTUzLGPZrVYxCwtgD3E=|SsDSxlYsCKbULcrOx5lsyz++Q8WkChj99aCGsB1pU0QUG4PVe0vLwUHOKL1dkL+1XmAPsWK4yR+RfcdZymwoNg=="
            hello = PSC.mkPassword "hello"
        encrypted <- liftIO $ PSC.hashPassword $ hello 
        assertEq "hashes are equal" (PSC.checkPassword hello encrypted) (PSC.checkPassword hello withScrypt)
