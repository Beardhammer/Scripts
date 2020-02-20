function sort-ipaddress ($textfile)
    {
    $myfile = Get-Content $textfile
    $sorted = @()
    foreach ($ip in $myfile){
        $ip = ([System.Net.IPAddress]$ip).GetAddressBytes()
        #convert to little endian
        [array]::Reverse($ip)
        #convert to an integer and add to array
        $sorted += ([System.Net.IPAddress]$ip).Address
    }
    #sort the array
    $sorted = $sorted | Sort-Object
    foreach ($address in $sorted){
        $address = ([System.Net.IPAddress]$address).GetAddressBytes()
        #convert back to ipaddress and reverse back to big endian
        [array]::Reverse($address)
        $address -join '.'
        }
    }
    sort-ipaddress C:\path\to\file
