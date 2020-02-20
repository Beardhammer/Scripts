#! /usr/bin/pwsh
param([string]$cyphertext,
	[string]$key)
    $decrypted=@()
    $keyarray = $key.ToCharArray()
    for($i = 0; $i -lt $cyphertext.length; $i++){
        $decrypted +=[char]([char][byte]$cyphertext[$i] -bxor $key[$i % $key.length])}
    try {$decoded = [char[]][int[]]($decrypted -join '' -split ' ') -join ''}
       catch{"Wrong Password";break}
    return $decoded
