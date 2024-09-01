rule detect_wmiexec_execution
{
meta:
author = "sajalbnsl"
description = "this rule detects cmd strings that indicate execution of wmiexec.py module of the Impacket framework"

strings:
$e1 = /wmiprvse.exe/ nocase
$e2 = /\w{3,20}\.\w+\s+\/\w+\s+\/\w+\s+[\w\s\-\.\/\:\\]+[\\\s]+1\>\s+[\\]+[\d\.]+[\\]+ADMIN\$[\\]+[\_\d\.]+\s+2\>\&1/ nocase

condition:
all of them
}
