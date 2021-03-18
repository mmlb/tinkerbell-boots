let _pkgs = import <nixpkgs> { };
in { pkgs ? import (_pkgs.fetchFromGitHub {
  owner = "NixOS";
  repo = "nixpkgs";
  #branch@date: nixpkgs-unstables@2021-01-25
  rev = "ce7b327a52d1b82f82ae061754545b1c54b06c66";
  sha256 = "1rc4if8nmy9lrig0ddihdwpzg2s8y36vf20hfywb8hph5hpsg4vj";
}) { } }:

with pkgs;

mkShell {
  buildInputs = [
    (docker.override { buildxSupport = true; })
    gcc
    git-lfs
    gnumake
    go
    golangci-lint
    go-bindata
    mockgen
    nixfmt
    nodePackages.prettier
    pkgsCross.aarch64-multiplatform.buildPackages.gcc
    protobuf
    shfmt
    shellcheck
    xz
  ];
}
