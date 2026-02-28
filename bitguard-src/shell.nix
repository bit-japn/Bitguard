{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    (python311.withPackages (ps: with ps; [
      fastapi
      uvicorn
      sqlalchemy
      requests
      cryptography
      pydantic
      pyinstaller
    ]))

    # native libs PyInstaller + cryptography need
    zlib
    openssl
    libffi
    stdenv.cc.cc.lib
  ];

  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [
      pkgs.zlib
      pkgs.openssl
      pkgs.libffi
      pkgs.stdenv.cc.cc.lib
    ]}
  '';
}
