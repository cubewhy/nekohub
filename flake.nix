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
            #: Note: change the options there
            #: You can delete unused options

            #: Languages {{{
            #: Rust {{{
            blackbox.languages.rust = {
              enable = true;
              #: version: available values ["stable" "beta" "nightly" "nightly-<date>"]
              version = "stable";
              components = ["rustc" "cargo" "clippy" "rustfmt" "rust-analyzer"];
              #: any rust targets, like x86_64-pc-windows-gnu, leave blank to use platform default
              #: the blackbox flake contains the Windows cross-compile workaround (pthreads).
              #: But please notice that you may still need to tackle with 3rd party libraries like
              #: openssl
              targets = [
                # "x86_64-pc-windows-gnu"
              ];
            };
            #: }}}

            #: C/C++ {{{
            blackbox.languages.c = {
              enable = false;
              #: compiler: available values ["gcc" "clang"]
              compiler = "gcc";
            };
            #: }}}

            #: Javascript/Typescript {{{
            #: tags: javascript, typescript, js, ts, nodejs, npm, pnpm, yarn
            blackbox.languages.javascript = {
              enable = false;
              #: Node.js package to use
              package = pkgs.nodejs;
              #: manager: available values ["npm" "pnpm" "yarn"]
              manager = "npm";
              #: Auto run `npm install` (or with other package managers) if package.json exist
              autoInstall = true;
            };
            #: }}}

            #: Java {{{
            blackbox.languages.java = {
              enable = false;
              package = pkgs.jdk;

              #: Java build tools
              maven = {
                enable = false;
                package = pkgs.maven;
              };

              gradle = {
                enable = false;
                package = pkgs.gradle;
              };
            };
            #: }}}

            #: Golang {{{
            blackbox.languages.go = {
              enable = false;
              version = "latest";
              #: enabled installTools option to install gopls, delve, golangci-lint, gotools
              installTools = false;
            };
            #: }}}

            #: }}}

            #: Libraries {{{
            blackbox.libraries = {
              #: OpenSSL {{{
              openssl.enable = false;
              #: }}}

              #: Cuda: {{{
              #: See https://nixos-cuda.org/ for enabling nix cuda cache
              cuda = {
                enable = false;
                #: version: e.g.  [11, 12, 13]
                version = "13";
                #: Enable this to install nvidia_x11 package
                withDrivers = true;
              };
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
        };
      });
  };
}
