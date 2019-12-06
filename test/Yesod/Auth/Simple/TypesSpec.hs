{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.Simple.TypesSpec (spec) where

import           Data.Aeson (encode)
import           TestImport

spec :: Spec
spec =

  describe "Password" $ do

    describe "Show instance" $
      it "redacts password" $
        show (Password "strongpass") `shouldBe` "<redacted>"

    describe "ToJSON instance" $
      it "redacts password" $
        encode (Password "strongpass") `shouldBe` "\"<redacted>\""
