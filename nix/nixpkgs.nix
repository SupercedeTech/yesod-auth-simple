let
  owner = "NixOS";
  repo = "nixpkgs";
  rev = "b2448a9fde1225c3681e576ab4d35d68631ca75e";
  url = "https://github.com/${owner}/${repo}/archive/${rev}.tar.gz";
in
  import (builtins.fetchTarball url)
