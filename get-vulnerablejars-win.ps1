gcim win32_volume | ? { $_.DriveType -eq 3 -and $_.DriveLetter -ne $null} `
	| % {(gci ($_.DriveLetter+"\") -rec -force -include *.jar -ea 0 `
	| % {sls "JndiLookup.class" $_} `
	| select -exp Path)} | out-file \\servername\share$\vulnerable-jar-$env:computername.txt
