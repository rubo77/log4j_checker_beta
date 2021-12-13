#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

echo "### locate files containing log4j ..."
OUTPUT="$(locate log4j|grep -v log4js)"
if [ "$OUTPUT)" ]; then
  echo "### maybe vulnerable, those files contain the name:"
  echo "$OUTPUT"
fi;
if [ "$(command -v yum)" ]; then
  echo "### check installed yum packages ..."
  OUTPUT="$(yum list installed|grep log4j|grep -v log4js)"
  if [ "$OUTPUT" ]; then
    echo "### maybe vulnerable, yum installed packages:"
    echo "$OUTPUT"
  fi;
fi;
if [ "$(command -v dpkg)" ]; then
  echo "### check installed dpkg packages ..."
  OUTPUT="$(dpkg -l|grep log4j|grep -v log4js)"
  if [ "$OUTPUT" ]; then
    echo "### maybe vulnerable, dpkg installed packages:"
    echo "$OUTPUT"
  fi;
fi;
if [ "$(command -v java)" ]; then
  echo "### java is installed"
  echo "so note that Java applications often bundle their libraries inside jar/war/ear files, so there still could be log4j in such applications.";
fi;
echo "______________________________________________________________________________________________________________";
echo "If you see no uncommented output above this line, you are safe. Otherwise check the listed files and packages.";
