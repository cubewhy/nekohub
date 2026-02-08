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
  ];

  # https://devenv.sh/languages/
  languages = {
    rust.enable = true;
  };

  env = {
    OPENSSL_DIR = "${pkgs.openssl.dev}";
    OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
    OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
  };

  git-hooks.hooks.sqlx-prepare = {
    enable = true;
    name = "update sqlx offline cache";
    entry = "bash -c 'cargo sqlx prepare -- --all-targets && git add .sqlx'";
    files = "\\.(rs|sql)$";
    language = "system";
    pass_filenames = false;
  };

  # See full reference at https://devenv.sh/reference/options/
}
