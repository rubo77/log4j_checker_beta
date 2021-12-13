echo "checking for log4j vulnerability...";
if [ "$(locate log4j|grep -v log4js)" ]; then
  echo "### maybe vulnerable, those files contain the name:";
  locate log4j|grep -v log4js;
fi;
if [ "$(command -v yum)" ]; then
  if [ "$(yum list installed|grep log4j|grep -v log4js)" ]; then
    echo "### maybe vulnerable, yum installed packages:";
    dpkg -l|grep log4j;
  fi;
fi;
if [ "$(command -v dpkg)" ]; then
  if [ "$(dpkg -l|grep log4j|grep -v log4js)" ]; then
    echo "### maybe vulnerable, dpkg installed packages:";
    dpkg -l|grep log4j;
  fi;
fi;
if [ "$(command -v java)" ]; then
  echo "java is installed, so note that Java applications often bundle their libraries inside jar/war/ear files, so there still could be log4j in such applications.";
fi;
echo "If you see no output above this line, you are safe. Otherwise check the listed files and packages.";
