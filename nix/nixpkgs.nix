let
  # release-22.05, committed on 2022.07.04
in
  import (builtins.fetchGit {
          url = "https://github.com/NixOS/nixpkgs";
          rev = "dbb62c34bbb5cdf05f1aeab07638b24b0824d605";
          ref = "nixos-22.05";
        })
