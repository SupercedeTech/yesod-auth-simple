{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.Simple.TypesSpec (spec) where

import           Data.Aeson (encode)
import           TestImport

spec :: Spec
spec =

  describe "Password" $ do

    describe "Show instance" $
      it "redacts password hash" $
        show (Password "strongpass hashed") `shouldBe` "<redacted>"

    describe "ToJSON instance" $
      it "redacts password" $
        encode (Password "strongpass hashed") `shouldBe` "\"strongpass hashed\""
