{-# OPTIONS_GHC -fno-warn-orphans #-}
module Yesod.Auth.Simple.Instance.Persist.EmailText where

import ClassyPrelude
import Database.Persist.Sql
import Yesod.Auth.Simple.Types

instance PersistFieldSql Email where
  sqlType = const SqlString

instance PersistField Email where
  toPersistValue (Email e) = toPersistValue e
  fromPersistValue (PersistText e) = Right $ Email e
  fromPersistValue e               = Left $ pack "Not a PersistText: " <> tshow e
