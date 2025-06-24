{
  description = "Where Am I - WiFi positioning using Apple WPS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_24
            buf
            protobuf
            protoc-gen-go
            git
            # Additional tools for development
            gopls
            golangci-lint
            delve
          ];

          shellHook = ''
            echo "🌍 Where Am I - Development Environment"
            echo "Go version: $(go version)"
            echo "Buf version: $(buf --version)"
            echo "Protobuf version: $(protoc --version)"
            echo ""
            echo "Available commands:"
            echo "  go run cmd/where-am-i/main.go --help"
            echo "  buf generate"
            echo "  go build -o bin/where-am-i cmd/where-am-i/main.go"
            echo ""
          '';

          # Set environment variables
          CGO_ENABLED = "0";
          GOOS = "linux";
        };
      });
}
