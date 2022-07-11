{ compiler }:
{ packageOverrides = pkgs: {
    haskell = pkgs.haskell // {
      packages = pkgs.haskell.packages // {
        "${compiler}" = pkgs.haskell.packages."${compiler}".override {
          overrides = hpNew: hpOld: rec {
            zxcvbn-hs = (hpNew.callPackage ./zxcvbn-hs.nix {});
            password = (pkgs.haskell.lib.dontCheck hpOld.password);
          };
        };
      };
    };
  };
}
