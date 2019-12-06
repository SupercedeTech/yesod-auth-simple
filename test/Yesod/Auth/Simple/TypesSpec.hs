{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.Simple.TypesSpec (spec) where

import           Data.Aeson (encode)
import           TestImport

spec :: Spec
spec = do

  describe "Password" $ do
    describe "Show instance" $ do
      it "redacts password" $ do
        show (Password "strongpass") `shouldBe` "<redacted>"

    describe "ToJSON instance" $ do
      it "redacts password" $ do
        encode (Password "strongpass") `shouldBe` "\"<redacted>\""
