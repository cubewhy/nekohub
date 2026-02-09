{
  pkgs,
  lib,
  config,
  ...
}: {
  # https://devenv.sh/packages/
  packages = with pkgs; [
    podman
    docker-compose
    openssl
    pkg-config
    sqlx-cli
    bash
    git
    pre-commit
  ];

  # https://devenv.sh/languages/
  languages = {
    rust.enable = true;
  };

  dotenv.enable = true;

  env = {
    OPENSSL_DIR = "${pkgs.openssl.dev}";
    OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
    OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
  };

  enterShell = ''
    pre-commit install
  '';

  # Note: do not add git hooks config in devenv.nix

  # See full reference at https://devenv.sh/reference/options/
}
