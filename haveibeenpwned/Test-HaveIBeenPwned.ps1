<#
    .SYNOPSIS
        Tests if an email account/password/domain has been exposed in any data breaches.

    .DESCRIPTION
        You can
            1. verify if an email account/password or domain has been exposed in any data breaches
            2. get a list of all existing data classes in the system.
            3. get all pastes for an account

        All this information is based on https://haveibeenpwned.com website
        Thanks to Troy Hunt (@troyhunt) to make this info available

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType BreachedAccount -EmailAddress test@example.com

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType PwnedPasswords -Password P@55w0rd

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType AllBreachedSites
        Test-HaveIBeenPwned.ps1 -ValidationType AllBreachedSites -Domain adobe.com

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType SingleBreachedSite -SiteName Adobe

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType DataClasses

    .EXAMPLE
        Test-HaveIBeenPwned.ps1 -ValidationType AllPastes -EmailAddress test@example.com

    .NOTES
        Author: Cláudio Silva (@ClaudioESSilva)
#>
[CmdletBinding(DefaultParameterSetName = 'BreachedAccount')]
[OutputType([object])]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('BreachedAccount', 'SingleBreachedSite', 'AllBreachedSites', 'DataClasses', 'AllPastes', 'PwnedPasswords')]
    [string]$ValidationType = 'BreachedAccount',
    [Parameter(Mandatory = $true, ParameterSetName = "Default")][Parameter(ParameterSetName = "BreachedAccount")][Parameter(ParameterSetName = "AllPastes")]
    [ValidatePattern("(\w+@[]a-zA-Z_]+?\.[a-zA-Z]{2,6})")]
    [string]$EmailAddress,
    [Parameter(Mandatory = $true, ParameterSetName = "Password")]
    [string]$Password,
    [Parameter(Mandatory = $true, ParameterSetName = "SingleBreachedSite")]
    [string]$SiteName,
    [Parameter(Mandatory = $true, ParameterSetName = "AllBreachedSites")]
    [string]$Domain
)
Begin {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    switch ($ValidationType) {
        'BreachedAccount' {
            $URI = "https://haveibeenpwned.com/api/v2/breachedaccount/$EmailAddress"
        }
        'AllBreachedSites' {
            if ($Domain) {
                $URI = "https://haveibeenpwned.com/api/v2/breaches?domain=$Domain"
            }
            else {
                $URI = "https://haveibeenpwned.com/api/v2/breaches"
            }
        }
        'SingleBreachedSite' {
            $URI = "https://haveibeenpwned.com/api/v2/breach/$SiteName"
        }
        'DataClasses' {
            $URI = "https://haveibeenpwned.com/api/v2/dataclasses"
        }
        'AllPastes' {
            $URI = "https://haveibeenpwned.com/api/v2/pasteaccount/$EmailAddress"
        }
        'PwnedPasswords' {
            $URI = "https://haveibeenpwned.com/api/v2/pwnedpassword/$Password"
        }
    }
}
Process {
    switch ($ValidationType) {
        {$_ -in @('BreachedAccount', 'AllBreachedSites', 'SingleBreachedSite', 'AllPastes')} {
            try {
                $request = Invoke-WebRequest -Uri $URI
                $response = ConvertFrom-Json $request
                return $response
            }
            catch [exception] {
                if ($ValidationType -eq 'SingleBreachedSite') {
                    Write-Warning "$SiteName was not found."
                }
                else {
                    Write-Warning "$EmailAddress was not found. $_"
                }
            }
        }
        # As this one only return a string array with values I have separated from the others
        'DataClasses' {
            try {
                $request = Invoke-WebRequest -Uri $URI
                $response = ConvertFrom-Json $request
                return $response
            }
            catch [exception] {
                Write-Warning "$_"
            }
        }
        'PwnedPasswords' {
            try {
                $request = Invoke-WebRequest -Uri $URI

                switch ($request.StatusCode) {
                    200 {
                        Write-Output "Oh no - pwned! This password has previously appeared in a data breach and should never be used. If you've ever used it anywhere before, change it immediately!"
                    }
                    400 {
                        Write-Warning "Bad request - the account does not comply with an acceptable format (i.e. it's an empty string)"
                    }
                    403 {
                        Write-Warning "Forbidden - no user agent has been specified in the request"
                    }
                    404 {
                        Write-Warning "Not found - the account could not be found and has therefore not been pwned"
                    }
                    429 {
                        Write-Warning "Too many requests - the rate limit has been exceeded"
                    }
                }
            }
            catch [exception] {
                Write-Warning "Error executing command for validation type 'PwnedPasswords'."
            }
        }
    }
}