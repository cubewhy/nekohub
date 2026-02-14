# vim:fileencoding=utf-8:foldmethod=marker
#: Tip: If you are using (n)vim, you can press zM to fold all the config blocks quickly (za to fold under cursor)
#: Tip: search keywords to start quickly
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    blackbox.url = "github:cubewhy/blackbox-flakes";

    #: Do not forget to modify the `overlays` variable below after you added new overlays

    #: Uncomment if you need Rust
    rust-overlay.url = "github:oxalica/rust-overlay";

    #: Uncomment if you need Golang
    # go-overlay.url = "github:purpleclay/nix-go";
  };

  outputs = {
    self,
    blackbox,
    rust-overlay,
    # go-overlay,
    nixpkgs,
    ...
  }: let
    overlays = [
      (import rust-overlay)
      # (import go-overlay)
    ];
  in {
    devShells =
      blackbox.lib.eachSystem {
        inherit nixpkgs overlays;
      } (pkgs: {
        default = blackbox.lib.mkShell {
          inherit pkgs;

          #: Config {{{
          config = {
            #: Languages {{{
            #: Rust {{{
            blackbox.languages.rust = {
              enable = true;
              #: version: available values ["stable" "beta" "nightly" "nightly-<date>"]
              channel = "stable";
              components = ["rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src"];
              #: any rust targets, like x86_64-pc-windows-gnu, leave blank to use platform default
              #: the blackbox flake contains the Windows cross-compile workaround (pthreads).
              #: But please notice that you may still need to tackle with 3rd party libraries like
              #: openssl
              targets = [
                # "x86_64-pc-windows-gnu"
              ];
            };
            #: }}}
            #: }}}

            #: Libraries {{{
            blackbox.libraries = {
              #: OpenSSL {{{
              openssl.enable = true;
              #: }}}
            };
            #: }}}

            #: Tools {{{
            blackbox.tools.pre-commit = {
              enable = true;
              #: Force run `pre-commit install` when enter shell
              #: This is not recommended, please don't enable it.
              runOnStart = false;
            };
            #: }}}
          };
          #: }}}

          #: mkShell builtin options are available
          # shellHook = ''
          # '';

          packages = [
            pkgs.sqlx-cli
          ];
        };
      });
  };
}
