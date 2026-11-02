#!/bin/bash
# usage: decomp.sh <binary(linux path)> <out.c>
HERE="$(cd "$(dirname "$0")" && pwd)"
export JAVA_HOME=$HOME/tools/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
P=$(mktemp -d)
$HOME/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless $P proj -import "$1" -scriptPath "$HERE" -postScript DecompileAll.java "$2" -deleteProject > "$2.log" 2>&1
tail -5 "$2.log"
