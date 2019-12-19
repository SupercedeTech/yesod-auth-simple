let
  owner = "hercules-ci";
  repo = "gitignore";
  rev = "f9e996052b5af4032fe6150bba4a6fe4f7b9d698";
in
  import (builtins.fetchTarball {
    url = "https://github.com/${owner}/${repo}/archive/${rev}.tar.gz";
    sha256 = "sha256:0jrh5ghisaqdd0vldbywags20m2cxpkbbk5jjjmwaw0gr8nhsafv";
  })
