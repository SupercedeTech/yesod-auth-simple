{ mkDerivation, aeson, base, base16-bytestring, base64-bytestring
, blaze-html, bytestring, clientsession, email-validate, hspec
, http-types, persistent, persistent-sqlite, scrypt, stdenv, text
, time, wai, yesod, yesod-auth, yesod-core, yesod-form, yesod-test
}:
mkDerivation {
  pname = "yesod-auth-simple";
  version = "0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base base16-bytestring base64-bytestring blaze-html
    bytestring clientsession email-validate http-types persistent
    scrypt text time wai yesod-auth yesod-core yesod-form
  ];
  testHaskellDepends = [
    base hspec persistent-sqlite yesod yesod-core yesod-form yesod-test
  ];
  description = "Traditional email/pass auth for Yesod";
  license = stdenv.lib.licenses.bsd3;
}
