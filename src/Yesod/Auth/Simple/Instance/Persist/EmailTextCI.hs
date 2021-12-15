{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE LambdaCase #-}
module Yesod.Auth.Simple.Instance.Persist.EmailTextCI where

import ClassyPrelude
import Database.Persist.Sql
import Yesod.Auth.Simple.Types

instance PersistFieldSql Email where
  sqlType _ = SqlOther $ pack "citext"

instance PersistField Email where
  toPersistValue (Email e) = toPersistValue e
  fromPersistValue = \case
    -- use `PersistLiteral_ Escaped bs` in newer persistent
    PersistDbSpecific bs -> Right $ Email (decodeUtf8 bs)
    e -> Left $ pack "Not a PersistDbSpecific: " <> tshow e
