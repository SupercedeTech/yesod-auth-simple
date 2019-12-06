{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.Simple.TypesSpec (spec) where

import           TestImport

spec :: Spec
spec = do

  describe "Password" $ do
    describe "Show instance" $ do
      it "redacts password" $ do
        show (Password "strongpass") `shouldBe` "<redacted>"
