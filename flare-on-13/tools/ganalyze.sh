#!/bin/bash
# usage: ganalyze.sh <projdir> <projname> <binary>   (import+analyze, keep project)
export JAVA_HOME=$HOME/tools/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
mkdir -p "$1"
$HOME/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless "$1" "$2" -import "$3" -max-cpu 16 > "$1/$2.analyze.log" 2>&1
tail -3 "$1/$2.analyze.log"
