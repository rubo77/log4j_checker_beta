#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta
# modified by Thomas Dankert <thomas.dankert@stihl.de>

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

# optionally scans the entire disk (using ionice)

# regular expression, check the following packages
PACKAGES='solr\|elastic\|log4j'

# IO load definition (1 = realtime, 2 = best-effort (priority 0-7), 3 = idle)
IONICE='ionice -c 2 -n 7'

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"

LANG=

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
  if [ "$(command -v locate)"]; then
    information "Using locate, which may use an outdated database. Please run updatedb to refresh it."
    locate log4j
  fi
}

function scan_filesystem() {
  $IONICE find / -iname log4j-core-*.jar 2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

function scan_in_archive_files() {
  $IONICE find / -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" \
    2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$' \
    | while read file; do
      unzip -l $file 2>/dev/null \
      | grep -H --label $file JndiLookup.class \
        2>/dev/null
    done
}

# check root user
if [ $USER != root ]; then
  warning "Please run this script as the root user, otherwise not all files will be found."
fi

# first scan: use locate
echo
information "Looking for files containing log4j..."
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, found log4j in the following files:"
  printf "%s\n" "$OUTPUT"
else
  ok "No files containing log4j"
fi

# second scan: use package manager
echo
information "Checking installed packages: ($PACKAGES)"
if [ "$(command -v yum)" ]; then
  # using yum
  OUTPUT="$(yum list installed | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No yum packages found"
  fi
fi
if [ "$(command -v dpkg)" ]; then
  # using dpkg
  OUTPUT="$(dpkg -l | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No dpkg packages found"
  fi
fi

# third scan: check for "java" command
echo
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


# ask for confirmation for filesystem scan
echo 
read -p "Do you want to scan the filesystem for log4j-core-*.jar and JndiLookup.class? [Y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  # perform best-effort (lowest priority) find call for log4j-core jar
  information "Checking filesystem for log4j-core-*.jar..."
  OUTPUT="$(scan_filesystem)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, found the log4j jar in the following files:"
    printf "%s\n" "$OUTPUT"
  fi

  # perform best-effort find call for all jars, and search for JndiLookup.class inside
  echo
  information "Analyzing JAR/WAR/EAR files..."
  OUTPUT="$(scan_in_archive_files)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, the following files contain the JndiLookup.class:"
    printf "%s\n" "$OUTPUT"
  fi
fi

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so even if 'java' is not installed, one of the applications could still be vulnerable."
fi

echo
warning "This script does not guarantee that you are not vulnerable, but is a strong hint."
echo
