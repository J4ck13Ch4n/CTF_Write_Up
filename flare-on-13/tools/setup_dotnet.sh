#!/bin/bash
cd ~/tools
curl -sSL -o dotnet-install.sh https://dot.net/v1/dotnet-install.sh
bash dotnet-install.sh --channel 10.0 --install-dir ~/tools/dotnet >/dev/null 2>&1
export DOTNET_ROOT=~/tools/dotnet
export PATH=~/tools/dotnet:/usr/bin:/bin
dotnet --list-sdks
dotnet tool install --tool-path ~/tools/dntools ilspycmd 2>&1 | tail -2
