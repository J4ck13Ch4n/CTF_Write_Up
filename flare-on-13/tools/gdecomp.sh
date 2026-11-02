#!/bin/bash
# usage: gdecomp.sh <projdir> <projname> <out.c> <addr> [addr...]
HERE="$(cd "$(dirname "$0")" && pwd)"
export JAVA_HOME=$HOME/tools/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
P="$1"; N="$2"; O="$3"; shift 3
$HOME/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless "$P" "$N" -process -noanalysis -readOnly -scriptPath "$HERE" -postScript DecompAt.java "$O" "$@" > "$O.log" 2>&1
tail -2 "$O.log"
