{ pkgs ? import ./nixpkgs.nix { inherit config; }
, compiler ? "ghc902"
, config ? import ./pkgconfig.nix { inherit compiler; }
, ... }:
rec {
  yesod-auth-simple = import ../default.nix {inherit compiler; inherit pkgs; inherit config;};

  shell = import ../shell.nix;

  test = pkgs.nixosTest rec {
    name = "yesod-auth-simple-test";

    nodes.server = { config, pkgs, ... }: {};

    testScript = ''
      server.start()
      server.succeed('YESOD_ENV=CI ${yesod-auth-simple}/bin/${name}')
    '';
  };
}
