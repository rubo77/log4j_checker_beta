#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

# regular expression, check the following packages:
PACKAGES='solr\|elastic\|log4j'

# Set this if you have a download for sha256 hashes
SHA256_HASHES_URL="$1"
# e.g. SHA256_HASHES_URL="https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/blob/main/sha256sums.txt"

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

export LANG=

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

# check root user
if [ $USER != root ]; then
  warning "You have no root-rights. Not all files will be found."
fi

dir_temp_hashes=$(mktemp -d)
file_temp_hashes="$dir_temp_hashes/vulnerable.hashes"
ok_hashes=
if [[ -n $SHA256_HASHES_URL && $(command -v wget) ]]; then
        wget  --max-redirect=0 --tries=2 --no-netrc -O "$file_temp_hashes.in" -- "$SHA256_HASHES_URL"
elif [[ -n $SHA256_HASHES_URL && $(command -v curl) ]]; then
        curl --globoff -f "$SHA256_HASHES_URL" -o "$file_temp_hashes.in"
fi
if [[ $? = 0 && -s "$file_temp_hashes.in" ]]; then
        cat "$file_temp_hashes.in" | cut -d" " -f1 | sort | uniq  > "$file_temp_hashes"
        ok_hashes=1
        information "Downloaded vulnerable hashes from ..."
fi

# first scan: use locate
echo
information "Looking for files containing log4j..."
if [ "$(command -v locate)" ]; then
  information "using locate, which could be using outdated data. besure to have called updatedb recently"
fi
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
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

# perform best-effort find call for all jars and optionally check against hashes
echo
information "Analyzing JAR/WAR/EAR files..."
if [ $ok_hashes ]; then
  information "Also checking hashes"
fi
if [ "$(command -v unzip)" ]; then
  find_jar_files | while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" \
      && warning "$jar_file contains log4j files"
    if [ $ok_hashes ]; then
      dir_unzip=$(mktemp -d)
      base_name=$(basename "$jar_file")
      unzip -qq -DD "$jar_file" '*.class' -d "$dir_unzip" \
        && find "$dir_unzip" -type f -not -name "*"$'\n'"*" -name '*.class' -exec sha256sum "{}" \; \
        | cut -d" " -f1 | sort | uniq > "$dir_unzip/$base_name.hashes";
      num_found=$(comm -12 "$file_temp_hashes" "$dir_unzip/$base_name.hashes" | wc -l)
      if [[ -n $num_found && $num_found != 0 ]]; then
        warning "$jar_file contains vulnerable binary classes"
      else
        ok "No .class files with known vulnerable hash found in $jar_file at first level."
      fi
      rm -rf -- "$dir_unzip"
    fi
  done
else
  information "Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)"
fi
[ $ok_hashes ] && rm -rf -- "$dir_temp_hashes"

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so even if 'java' is not installed, one of the applications could still be vulnerable."
fi

echo
warning "This script does not guarantee that you are not vulnerable, but is a strong hint."
echo
