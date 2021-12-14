#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

export LANG=

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"
# if you don't want colored output, set the variables to empty strings:
# RED=""; GREEN=""; YELLOW=""; ENDCOLOR=""

function warning() {
  printf "${RED}[WARNING] %s${ENDCOLOR}\n" "$1" >&2
}

function information() {
  printf "${YELLOW}[INFO] %s${ENDCOLOR}\n" "$1"
}

function ok() {
  printf "${GREEN}[INFO] %s${ENDCOLOR}\n" "$1"
}

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    locate log4j
  else
    find \
      /var /etc /usr /opt /lib* \
      -name "*log4j*" \
      2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$'
  fi
}

function find_jar_files() {
  find \
    /var /etc /usr /opt /lib* \
    -name "*.jar" \
    -o -name "*.war" \
    -o -name "*.ear" \
    2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

information "Looking for files containing log4j..."
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
  printf "%s\n" "$OUTPUT"
else
  ok "No files containing log4j"
fi

if [ "$(command -v yum)" ]; then
  information "Checking installed yum packages..."
  OUTPUT="$(yum list installed | grep -i 'solr\|elastic\|log4j' | grep -iv log4js)"

  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No yum packages found"
  fi
fi

if [ "$(command -v dpkg)" ]; then
  information "Checking installed dpkg packages..."
  OUTPUT="$(dpkg -l | grep -i 'solr\|elastic\|log4j' | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No dpkg packages found"
  fi
fi

information "Checking if Java is installed..."
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  warning "Java is installed"
  printf "     %s\n     %s\n" \
    "Java applications often bundle their libraries inside binary files," \
    "so there could be log4j in such applications."
else
  ok "Java is not installed"
fi

if [ "$(command -v unzip)" ]; then
  information "Analyzing JAR/WAR/EAR files..."
  find_jar_files | while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" \
      && warning "$jar_file contains log4j files"
  done
else
  information "Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)"
fi

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so 'java' might not be installed but one such apps could still be vulnerable."
fi
echo
warning "This whole script is not 100% proof you are not vulnerable, but a strong hint"
echo
