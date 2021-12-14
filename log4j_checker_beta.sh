#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

export LANG=

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"

function warning() {
  printf "${RED}[WARNING] %s${ENDCOLOR}\n" "$1" >&2
}

function information() {
  printf "${YELLOW}[INFO] %s${ENDCOLOR}\n" "$1"
}

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    locate log4j
  else
    find \
      /var /etc /usr /lib* \
      -name "*log4j*" \
      2>&1 \
      | grep -v '^find:.* Permission denied$'
  fi
}

information "Looking for files containing log4j..."
OUTPUT="$(locate_log4j | grep -v log4js)"
if [ "$OUTPUT" ]
then
  warning "Maybe vulnerable, those files contain the name:"
  printf "%s\n" "$OUTPUT"
fi

if [ "$(command -v yum)" ]; then
  information "Checking installed yum packages..."
  OUTPUT="$(yum list installed | grep -i log4j | grep -v log4js)"

  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    printf "%s\n" "$OUTPUT"
  fi
fi

if [ "$(command -v dpkg)" ]; then
  information "Checking installed dpkg packages..."
  OUTPUT="$(dpkg -l | grep -i log4j | grep -v log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    printf "%s\n" "$OUTPUT"
  fi
fi

information "Checking if Java is installed..."
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  warning "Java is installed"
  printf "     %s\n     %s\n" \
    "Java applications often bundle their libraries inside jar/war/ear files," \
    "so there still could be log4j in such applications."
else
  information "Java is not installed"
fi
information "_________________________________________________"
echo "If you see no uncommented output above this line, you are safe. Otherwise check the listed files and packages.";
if [ "$JAVA" == "" ]; then
  echo "Some apps bundle the vulnerable library in their own compiled package, so 'java' might not be installed but one such apps could still be vulnerable."
fi
printf "\nNote: this is not 100% proof you are not vulnerable, but a strong hint!\n"
