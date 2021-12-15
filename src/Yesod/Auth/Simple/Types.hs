{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.Simple.Types where

import ClassyPrelude
import Data.Aeson
import qualified Text.Password.Strength as PW

newtype PasswordReq = PasswordReq { unPasswordReq :: Text }

-- | `extraWords` are common words, likely in the application domain,
-- that should be noted in the zxcvbn password strength check. These
-- words will not be banned in passwords, but they will be noted as
-- less secure than they could have been otherwise.
data PasswordCheck = RuleBased { minChars :: Int }
                   | Zxcvbn { minStrength :: PW.Strength
                            , extraWords  :: Vector Text }

data PasswordStrength = GoodPassword PW.Strength
                      | BadPassword PW.Strength (Maybe Text)

instance ToJSON PasswordStrength where
  toJSON (GoodPassword stren) =
    object ["isAcceptable" .= True, "score" .= fromEnum stren]
  toJSON (BadPassword stren mErr) =
    object [ "isAcceptable" .= False
           , "score" .= fromEnum stren
           , "error" .= toJSON mErr ]

instance FromJSON PasswordReq where
  parseJSON = withObject "req" $ \o -> do
    password <- o .: "password"
    return $ PasswordReq password

newtype Email = Email { unEmail :: Text }
  deriving (Show, ToJSON, FromJSON)

instance Eq Email where
  Email e1 == Email e2 = toLower e1 == toLower e2

newtype Password = Password Text
  deriving(Eq, ToJSON, FromJSON)

instance Show Password where
  show _ = "<redacted>"

type VerUrl = Text
