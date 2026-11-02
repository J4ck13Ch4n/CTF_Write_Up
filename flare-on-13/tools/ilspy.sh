#!/bin/bash
# usage: ilspy.sh <dll> <outdir>
export DOTNET_ROOT=~/tools/dotnet
export PATH=~/tools/dotnet:/usr/bin:/bin
export DOTNET_ROLL_FORWARD=Major
~/tools/dntools/ilspycmd -p -o "$2" "$1"
