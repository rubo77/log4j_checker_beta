#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

OPTIND=1
VERBOSITY=0
DEBUG=0
EXTRA_DIRS=
SHA256_HASHES_URL=
PROGNAME="${0##*/}"
VERSION="1.0"

function show_help {
cat <<%
Usage: ${PROGNAME} [SHA256_HASHES_URL] [-hvdV] [-e path list] [-u SHA256_HASHES_URL]

  -h show this help
  -v verbose
  -V Version
  -d debug
  -u SHA256_HASHES_URL (this can be added without -f also)
  -e extra directories to search (e.g. -e "/data /media")
%
}

while getopts "Vh?vdu:e:" opt; do
  case "$opt" in
    h|\?)
      show_help
      exit 0
      ;;
    v)
      VERBOSITY=$(( ${VERBOSITY} + 1 ))
      ;;
    d)
      DEBUG=1
      VERBOSITY=10
      set -x
      ;;
    e)
      EXTRA_DIRS=$OPTARG
      ;;
    u)
      SHA256_HASHES_URL=$OPTARG
      ;;
    V)
      echo "${PROGNAME} ${VERSION}"
      exit 0
      ;;
  esac
done

shift $((OPTIND-1))

[ "${1:-}" = "--" ] && shift

# regular expression, check the following packages:
PACKAGES='solr\|elastic\|log4j'

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

if [ "$SHA256_HASHES_URL" = "" ]; then
  SHA256_HASHES_URL="$@"
fi
if [ "$SHA256_HASHES_URL" = "" ]; then
  information "using default hash file. If you want to use other hashes, set another URL as first argument"
  SHA256_HASHES_URL="https://raw.githubusercontent.com/rubo77/log4j_checker_beta/main/hashes-pre-cve.txt"
fi

# echo "VERBOSITY=$VERBOSITY, EXTRA_DIRS='$EXTRA_DIRS', SHA256_HASHES_URL='$SHA256_HASHES_URL', Leftovers: $@"; exit

export LANG=

DIRS_TO_SEARCH="/var /etc /usr /opt /lib*"

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      # Mac OSX
      locate -i log4j
    else
      locate -ei log4j
    fi
  else
    find \
      $DIRS_TO_SEARCH $EXTRA_DIRS \
      -iname "*log4j*" 2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$'
  fi
}

function find_jar_files() {
  find \
    $DIRS_TO_SEARCH $EXTRA_DIRS \
    -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" 2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

# check root user
if [ "$EUID" -ne 0 ]; then
  warning "You have no root-rights. Not all files will be found."
fi

dir_temp_hashes=$(mktemp -d -t ${PROGNAME}_XXXXXX)
file_temp_hashes="$dir_temp_hashes/vulnerable.hashes"
ok_hashes=
regex='^[httpsfile]+://.*$'
if [[ -n $SHA256_HASHES_URL && $SHA256_HASHES_URL =~ $regex ]]; then
  if [ $(command -v wget) ]; then
    wget -q --max-redirect=0 --tries=2 -O "$file_temp_hashes.in" -- "$SHA256_HASHES_URL"
  elif [ $(command -v curl) ]; then
    curl -s --globoff -f "$SHA256_HASHES_URL" -o "$file_temp_hashes.in"
  else
    warning "Neither wget nor curl is installed. The hash file cannot be downloaded"
  fi
else
  information "Using the local file '$SHA256_HASHES_URL'"
  cp "$SHA256_HASHES_URL" "$file_temp_hashes.in"
fi
if [[ $? = 0 && -s "$file_temp_hashes.in" ]]; then
  cat "$file_temp_hashes.in" | cut -d" " -f1 | sort | uniq  > "$file_temp_hashes"
  ok_hashes=1
  ok "Created vulnerable hashes file from $SHA256_HASHES_URL"
else
  warning "Couldn't create hash file"
fi

# first scan: use locate
echo
information "Looking for files containing log4j..."
if [ "$(command -v locate)" ]; then
  information "Using locate, which could be using outdated data. Be sure to have called updatedb recently"
else
  information "locate is not installed, using slower find method"
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
  information "   Java applications often bundle their libraries inside binary files,"
  information "   so there could be log4j in such applications."
else
  ok "Java is not installed"
fi

# perform best-effort find call for all jars and optionally check against hashes
echo
information "Analyzing JAR/WAR/EAR files in $DIRS_TO_SEARCH $EXTRA_DIRS ..."
if [ $ok_hashes ]; then
  information "Also checking hashes"
fi
COUNT=0
COUNT_FOUND=0
if [ "$(command -v unzip)" ]; then
  
  # incect find_jar_files at the end of the while loop to prevent extra shell
  while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" && \
      echo && \
      warning "[$COUNT - contains log4j files] $jar_file"
    COUNT=$(($COUNT + 1))
    if [ $ok_hashes ]; then
      base_name=$(basename "$jar_file")
      dir_unzip="$dir_temp_hashes/java/$COUNT""_$( echo "$base_name" | tr -dc '[[:alpha:]]')"
      mkdir -p "$dir_unzip"

      if [[ $(command -v sha256sum) ]]; then
        SHA256SUM_COMMAND="sha256sum"
        SHA256SUM_POS=1
      else
        $SHA256SUM_COMMAND="openssl dgst -sha256"
        SHA256SUM_POS=2
      fi
      unzip -qq -DD "$jar_file" '*.class' -d "$dir_unzip" 2> /dev/null \
      && find "$dir_unzip" -type f -not -name "*"$'\n'"*" -iname '*.class' -exec $SHA256SUM_COMMAND "{}" \; \
      | cut -d" " -f$SHA256SUM_POS | sort | uniq > "$dir_unzip/$base_name.hashes";

      if [ -f "$dir_unzip/$base_name.hashes" ]; then
        if [ $VERBOSITY -gt 1 ]; then
          information "[$COUNT] searching hash of $dir_unzip/$base_name.hashes in $file_temp_hashes"
        fi
        num_found=$(comm -12 "$file_temp_hashes" "$dir_unzip/$base_name.hashes" | wc -l)
      else
        num_found=0
      fi
      if [[ -n $num_found && $num_found != 0 ]]; then
        echo
        warning "[$COUNT - vulnerable binary classes] $jar_file"
        COUNT_FOUND=$(($COUNT_FOUND + 1))
      elif [ $VERBOSITY -gt 0 ]; then
        ok "[$COUNT] No .class files with known vulnerable hash found in $jar_file at first level."
        # TODO: if there are packed files inside, search recursively
      else
        printf "."
      fi
      # delete temp folder containing the extracted java files
      if [ $DEBUG == 0 ]; then
        rm -rf -- "$dir_unzip"
      fi
    fi
  done <<<"$(find_jar_files)"
  
  echo
  if [ $COUNT -gt 0 ]; then
    information "Found $COUNT files in unpacked binaries containing the string 'log4j' with $COUNT_FOUND vulnerabilities"
    if [ $COUNT_FOUND -gt 0 ]; then
      warning "Found $COUNT_FOUND vulnerabilities in unpacked binaries"
    fi
  fi
  if [ $DEBUG == 1 ]; then
    information "DEBUG MODE: the temporary directory is not deleted: $dir_temp_hashes"
  else
    # delete temp folder containing $file_temp_hashes
    [ $ok_hashes ] && rm -rf -- "$dir_temp_hashes"
  fi
else
  information 'Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)'
fi

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so even if 'java' is not installed, one of the applications could still be vulnerable."
fi

echo
warning "This script does not guarantee that you are not vulnerable, but is a strong hint."
echo
