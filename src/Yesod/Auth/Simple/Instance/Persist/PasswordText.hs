{-# OPTIONS_GHC -fno-warn-orphans #-}
module Yesod.Auth.Simple.Instance.Persist.PasswordText where

import ClassyPrelude
import Database.Persist.Sql
import Yesod.Auth.Simple.Types

instance PersistFieldSql Password where
  sqlType = const SqlString

instance PersistField Password where
  toPersistValue (Password e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Password e
  fromPersistValue e               = Left $ pack "Not a PersistText: " <> tshow e
