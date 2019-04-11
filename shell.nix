{ nixpkgs ? import <nixpkgs> {}, compiler ? "default", doBenchmark ? false }:

let

  inherit (nixpkgs) pkgs;

  f = { mkDerivation, aeson, base, base16-bytestring
      , base64-bytestring, bytestring, clientsession, email-validate
      , hspec, http-types, scrypt, stdenv, text, time, yesod-auth
      , yesod-core, yesod-form
      }:
      mkDerivation {
        pname = "yesod-auth-simple";
        version = "0.0.0";
        src = ./.;
        libraryHaskellDepends = [
          aeson base base16-bytestring base64-bytestring bytestring
          clientsession email-validate http-types scrypt text time yesod-auth
          yesod-core yesod-form
        ];
        testHaskellDepends = [ base hspec ];
        description = "Traditional email/pass auth for Yesod";
        license = stdenv.lib.licenses.bsd3;
      };

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  variant = if doBenchmark then pkgs.haskell.lib.doBenchmark else pkgs.lib.id;

  drv = variant (haskellPackages.callPackage f {});

in

  if pkgs.lib.inNixShell then drv.env else drv
