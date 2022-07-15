{ mkDerivation, fetchgit, lib, base,
  basement, memory, tasty, tasty-hunit, 
  tasty-kat, tasty-quickcheck
}:
mkDerivation {
  pname = "cryptonite";
  version = "0.30";
  src = fetchgit {
    url = "https://github.com/sethlivy/cryptonite";
    rev = "5549034b3b6268bc57113753c730dad1368305db";
    sha256 = null;
    fetchSubmodules = true;
  };
  libraryHaskellDepends = [
    base basement memory tasty tasty-hunit
    tasty-kat tasty-quickcheck
  ];
  homepage = "https://github.com/haskell-crypto/crpytonite";
  description = "lowlevel set of cryptographic primitives for haskell";
  license = lib.licenses.mit;
}
