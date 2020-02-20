$target_host = "http://docker.hackthebox.eu:"
$target_port = #porthere
$target = $target_host + $target_port
$useragent = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
$getrequest = Invoke-WebRequest -uri $target -Method GET -SessionVariable cookie
$getrequest.ParsedHtml.body.innerHTML -match "<H3 align=center>(\w+)" | out-null
$hashme = $Matches[1]
$hashed = (Get-FileHash -InputStream ([IO.MemoryStream]::new([text.encoding]::UTF8.GetBytes("$hashme"))) -Algorithm MD5).hash
$poster = Invoke-WebRequest -uri $target -Method POST -body "hash=$($hashed.tolower())" -WebSession $cookie
$poster.ParsedHtml.body.innerHTML
