echo "checking for log4j vulnerability...";
if [ "$(find / -name 'log4j*'|grep -v log4js)" ]; then
  echo "### maybe vulnerable, those files contain the name:";
  find / -name 'log4j*'|grep -v log4js;
fi;
if [ "$(dpkg -l|grep log4j|grep -v log4js)" ]; then
  echo "### maybe vulnerable, installed packages:";
  dpkg -l|grep log4j;
fi;
if [ "$(which java)" ]; then
  echo "java is installed, so note that Java applications often bundle their libraries inside jar/war/ear files, so there still could be log4j in such applications.";
fi;
echo "check done";
