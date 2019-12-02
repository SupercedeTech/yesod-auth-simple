{ mkDerivation, aeson, base, base16-bytestring, base64-bytestring
, blaze-html, bytestring, clientsession, email-validate, hspec
, http-types, persistent, persistent-sqlite, scrypt, stdenv, text
, time, vector, wai, yesod, yesod-auth, yesod-core, yesod-form
, yesod-test, zxcvbn-hs
}:
mkDerivation {
  pname = "yesod-auth-simple";
  version = "0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base base16-bytestring base64-bytestring blaze-html
    bytestring clientsession email-validate http-types persistent
    scrypt text time vector wai yesod-auth yesod-core yesod-form
    zxcvbn-hs
  ];
  testHaskellDepends = [
    base hspec persistent-sqlite vector yesod yesod-core yesod-form
    yesod-test
  ];
  description = "Traditional email/pass auth for Yesod";
  license = stdenv.lib.licenses.bsd3;
}
