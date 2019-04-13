{ mkDerivation, aeson, base, base16-bytestring, base64-bytestring
, blaze-html, bytestring, clientsession, email-validate, hspec
, http-types, scrypt, stdenv, text, time, wai, yesod-auth
, yesod-core, yesod-form
}:
mkDerivation {
  pname = "yesod-auth-simple";
  version = "0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base base16-bytestring base64-bytestring blaze-html
    bytestring clientsession email-validate http-types scrypt text time
    wai yesod-auth yesod-core yesod-form
  ];
  testHaskellDepends = [ base hspec ];
  description = "Traditional email/pass auth for Yesod";
  license = stdenv.lib.licenses.bsd3;
}
