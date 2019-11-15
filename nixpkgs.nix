let
  url = "https://github.com/NixOS/nixpkgs/archive/91d5b3f07d27622ff620ff31fa5edce15a5822fa.tar.gz";
in import (builtins.fetchTarball url)
