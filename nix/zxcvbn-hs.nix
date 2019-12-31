{ mkDerivation, attoparsec, base, base64-bytestring, binary
, binary-instances, containers, criterion, fgl, hedgehog, lens
, math-functions, stdenv, tasty, tasty-hedgehog, tasty-hunit, text
, time, unordered-containers, vector, zlib
}:
mkDerivation {
  pname = "zxcvbn-hs";
  version = "0.2.1.0";
  sha256 = "a811480d38390d58f30bf866053a848cf3aa37bd9bb7b90a4e9fda02c0cf6abf";
  revision = "2";
  editedCabalFile = "05l4pni4264rcivixzakjkph5qr4jr8qb4jbfj2nw106n1zhjaka";
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    attoparsec base base64-bytestring binary binary-instances
    containers fgl lens math-functions text time unordered-containers
    vector zlib
  ];
  executableHaskellDepends = [
    attoparsec base base64-bytestring binary binary-instances
    containers fgl lens math-functions text time unordered-containers
    vector zlib
  ];
  testHaskellDepends = [
    attoparsec base base64-bytestring binary binary-instances
    containers fgl hedgehog lens math-functions tasty tasty-hedgehog
    tasty-hunit text time unordered-containers vector zlib
  ];
  benchmarkHaskellDepends = [
    attoparsec base base64-bytestring binary binary-instances
    containers criterion fgl lens math-functions text time
    unordered-containers vector zlib
  ];
  homepage = "https://code.devalot.com/sthenauth/zxcvbn-hs";
  description = "Password strength estimation based on zxcvbn";
  license = stdenv.lib.licenses.mit;
}
