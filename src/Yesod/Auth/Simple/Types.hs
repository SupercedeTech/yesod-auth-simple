{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Yesod.Auth.Simple.Types where

import           ClassyPrelude
import           Data.Aeson
import           Database.Persist.Sql   (PersistField, PersistFieldSql,
                                         PersistValue (PersistText),
                                         SqlType (SqlString), fromPersistValue,
                                         sqlType, toPersistValue)
import qualified Text.Password.Strength as PW

newtype PasswordReq = PasswordReq { unPasswordReq :: Text }

-- | `extraWords` are common words, likely in the application domain,
-- that should be noted in the zxcvbn password strength check. These
-- words will not be banned in passwords, but they will be noted as
-- less secure than they could have been otherwise.
data PasswordCheck = RuleBased { minChars :: Int }
                   | Zxcvbn { minStrength :: PW.Strength
                            , extraWords  :: Vector Text }

instance FromJSON PasswordReq where
  parseJSON = withObject "req" $ \o -> do
    password <- o .: "password"
    return $ PasswordReq password

newtype Email = Email Text
  deriving (Eq, Show, ToJSON, FromJSON)

instance PersistFieldSql Email where
  sqlType = const SqlString

instance PersistField Email where
  toPersistValue (Email e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Email e
  fromPersistValue e               = Left $ "Not a PersistText: " <> tshow e

newtype Password = Password Text
  deriving (Eq, FromJSON)

instance Show Password where
  show _ = "<redacted>"

instance ToJSON Password where
  toJSON _ = String "<redacted>"

instance PersistFieldSql Password where
  sqlType = const SqlString

instance PersistField Password where
  toPersistValue (Password e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Password e
  fromPersistValue e               = Left $ "Not a PersistText: " <> tshow e

type VerUrl = Text

