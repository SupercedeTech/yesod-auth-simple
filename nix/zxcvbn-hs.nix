{ mkDerivation, aeson, attoparsec, base, base64-bytestring, binary
, binary-instances, containers, criterion, fetchgit, fgl, hedgehog
, lens, lib, math-functions, tasty, tasty-hedgehog, tasty-hunit
, text, time, unordered-containers, vector, zlib
}:
mkDerivation {
  pname = "zxcvbn-hs";
  version = "0.3.0.0";
  src = fetchgit {
    url = "https://github.com/SupercedeTech/zxcvbn-hs";
    sha256 = "0czwk9bx57a18kgb3sy6mfw1hvzm66msv7y357lr33pkwim73fgn";
    rev = "c9192ff4b05d4cbf5a6f6725510542782b962a91";
    fetchSubmodules = true;
  };
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson attoparsec base base64-bytestring binary binary-instances
    containers fgl lens math-functions text time unordered-containers
    vector zlib
  ];
  executableHaskellDepends = [
    aeson attoparsec base base64-bytestring binary binary-instances
    containers fgl lens math-functions text time unordered-containers
    vector zlib
  ];
  testHaskellDepends = [
    aeson attoparsec base base64-bytestring binary binary-instances
    containers fgl hedgehog lens math-functions tasty tasty-hedgehog
    tasty-hunit text time unordered-containers vector zlib
  ];
  benchmarkHaskellDepends = [
    aeson attoparsec base base64-bytestring binary binary-instances
    containers criterion fgl lens math-functions text time
    unordered-containers vector zlib
  ];
  homepage = "https://github.com/sthenauth/zxcvbn-hs";
  description = "Password strength estimation based on zxcvbn";
  license = lib.licenses.mit;
}
