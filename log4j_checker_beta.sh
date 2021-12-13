#!/bin/bash

# Run with:
# wget https://raw.githubusercontent.com/ad-aures/log4j_checker_beta/main/log4j_checker_beta.sh -q -O - |bash

echo "Installing locate package…"
sudo apt-get -qq update
sudo apt-get -qq -y install locate
sudo updatedb

echo "checking for log4j vulnerability...";
if [ "$(locate log4j|grep -v log4js)" ]; then
  echo "### maybe vulnerable, those files contain the name:";
  locate log4j|grep -v log4js;
fi;
if [ "$(dpkg -l|grep log4j|grep -v log4js)" ]; then
  echo "### maybe vulnerable, installed packages:";
  dpkg -l|grep log4j;
fi;
if [ "$(which java)" ]; then
  echo "java is installed, so note that Java applications often bundle their libraries inside jar/war/ear files, so there still could be log4j in such applications.";
fi;
echo "If you see no output above this line, you are safe. Otherwise check the listed files and packages.";
