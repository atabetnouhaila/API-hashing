$FunctionsToHash = @("CreateThread")

$FunctionsToHash | ForEach-Object {
    $function = $_
    
    $initialHash = 0x35
    [int]$counter = 0

    $function.ToCharArray() | ForEach-Object {
        $char = $_
        $charCode = [int64]$char
        $charCodeHex = '0x{0:x}' -f $charCode
        $initialHash += $initialHash * 0xab10f29f + $charCodeHex -band 0xffffff
        $finalHashHex = '0x{0:x}' -f $initialHash
        $counter++
        Write-Host "Iteration $counter : $char : $charCodeHex : $finalHashHex"
    }
    Write-Host "$function`t $('0x00{0:x}' -f $initialHash)"
}
