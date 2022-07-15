[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    $device_id
)
$client_id = "grjm3ku79we8ckce1rob"
$api_secret = "" 
#$device_id = "eb7e7904563c0df8a4zpef"
$baseUrl = "https://openapi.tuyaus.com" 
$unix_ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

function get-token { 
        $TokenUri = "/v1.0/token?grant_type=1"
        $fullUrl = $baseUrl + $TokenUri 

        $signature = new-signature -content '' -SignUri $TokenUri -method 'GET'

        $Header = @{
                "sign_method" = "HMAC-SHA256"
                "client_id" = $client_id
                "t" = $unix_ts
                "mode" = "cors"
                "Content-Type" = "application/json"
                "sign" = $signature
            }
        $result = Invoke-RestMethod -Uri $fullUrl -Headers $Header
        return $result.result.access_token
}


function new-signature($content, $SignUri, $token, $method) {
        # Generate content hash
        $client_id = "grjm3ku79we8ckce1rob"
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes(''))
        #[System.Text.Encoding]::ASCII.GetString($hash)
        $contentHash = ([Convert]::ToHexString($hash)).toLower()
        $array_tosign = @($method, $contentHash, '', $SignUri)
        $stringToSign = $array_tosign -join "`n"
        If($PSBoundParameters.ContainsKey("token")) {
                $signStr = $client_id + $token + $unix_ts + $stringToSign
        }
        else {
                $signStr = $client_id + $unix_ts + $stringToSign
        }

        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($api_secret)
        $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($signStr))
        $signature = [Convert]::ToHexString($signature)
        return $signature
}

# GET Device Info
$access_token = get-token
$devUri = "/v1.1/iot-03/devices"
$fullUrl = $baseUrl + $devUri + "/" + $device_id
$fullUri = $devUri + "/" + $device_id
$req_sign = new-signature '' $fullUri $access_token 'GET'
$Header = @{
        "sign_method" = "HMAC-SHA256"
        "client_id" = $client_id
        "access_token" = $access_token
        "t" = $unix_ts
        "mode" = "cors"
        "Content-Type" = "application/json"
        "sign" = $req_sign
    }
$result = Invoke-RestMethod -Uri $fullUrl -Headers $Header


# GET Factory Info
$devUri = "/v1.0/iot-03/devices/factory-infos?device_ids="
$fullUri = $devUri + $device_id
$fullUrl = $baseUrl + $devUri + $device_id

$req_sign = new-signature '' $fullUri $access_token 'GET'

$Header = @{
        "sign_method" = "HMAC-SHA256"
        "client_id" = $client_id
        "access_token" = $access_token
        "t" = $unix_ts
        "mode" = "cors"
        "Content-Type" = "application/json"
        "sign" = $req_sign
    }
$factoryInfo = Invoke-RestMethod -Uri $fullUrl -Headers $Header



# Format Return
    $result_table = [PSCustomObject]@{
        name      = $result.result.name
        model     = $result.result.model
        id        = $result.result.id
        macaddr   = $factoryInfo.result.mac
        local_key = $result.result.local_key
    }
$result_table
