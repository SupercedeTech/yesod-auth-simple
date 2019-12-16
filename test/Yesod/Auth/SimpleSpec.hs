{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Yesod.Auth.SimpleSpec (spec) where

import qualified Data.Text  as T
import           TestImport


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
        get $ AuthR $ confirmTokenR t
        _ <- followRedirect
        request $ do
          addToken
          setMethod "POST"
          setUrl $ AuthR confirmR
          -- NB: The following password would be fine without the
          -- commonDomainWords definition
          byLabelExact "Password" "hello yesod 123"
        r <- followRedirect
        assertEq "path is confirmation form" (Right (ur (AuthR confirmR))) r

    describe "with a password that is too long" $ do
      it "caps length at 150" $ do
        let email = "user@example.com"
            -- Not using a simple, eg, "a" replicate because that
            -- causes a bug hopefully soon fixed:
            -- github.com/sthenauth/zxcvbn-hs/issues/2
            password = T.replicate 12 "one two three" -- 156 chars
        ur <- runHandler getUrlRender
        t <- liftIO $ encryptRegisterToken (Email email)
        get $ AuthR $ confirmTokenR t
        _ <- followRedirect
        request $ do
          addToken
          setMethod "POST"
          setUrl $ AuthR $ confirmR
          byLabelExact "Password" password
        r <- followRedirect
        assertEq "path is confirmation form" (Right (ur (AuthR confirmR))) r

    describe "with an adequately strong password" $

      it "inserts a new user" $ do
        let email = "user@example.com"
        ur <- runHandler getUrlRender
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" email
        token <- liftIO $ encryptRegisterToken (Email email)
        get $ AuthR $ confirmTokenR token
        _ <- followRedirect
        request $ do
          setMethod "POST"
          setUrl $ AuthR $ confirmR
          byLabelExact "Password" "really difficult yesod password here"
        r <- followRedirect
        assertNotEq "path is not confirmation form" (Right (ur (AuthR confirmR))) r

    describe "with an invalid token" $

      it "renders the invalid token page" $ do
        let token = "not_a_valid_token"
        get $ AuthR registerR
        request $ do
          setMethod "POST"
          setUrl $ AuthR registerR
          byLabelExact "Email" "user@example.com"
        get $ AuthR $ confirmTokenR token
        _ <- followRedirect
        statusIs 400

    describe "with an email that is not unique" $

      it "automatically authenticates the existing user" $ do
        encrypted <- liftIO $ encryptPassIO' $ Pass "strongpass"
        let userEmail = Email  "user@example.com"
            userPassword = Password . decodeUtf8 . getEncryptedPass $ encrypted
        runDB' . insert_ $ User{..}

        token <- liftIO $ encryptRegisterToken userEmail
        get $ AuthR $ confirmTokenR token
        _ <- followRedirect
        statusIs 303
        r <- followRedirect
        ur <- runHandler getUrlRender
        assertEq "redirection successful" r (Right $ ur HomeR)
