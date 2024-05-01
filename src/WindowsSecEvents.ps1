# Powershell Functions for troubleshooting Windows Security Events connected with Morpheus

$StatusCodes = @{
    "0XC000005E"="There are currently no logon servers available to service the logon request.";
    "0xC0000064"="Misspelled or bad username";
    "0xC000006A"="Misspelled or bad password";
    "0XC000006D"="Bad username or authentication information";
    "0XC000006E"="Credentials OK but account restrictions prevent login";
    "0xC000006F"="User logon outside authorized hours";
    "0xC0000070"="User logon from unauthorized workstation";
    "0xC0000071"="User logon with expired password";
    "0xC0000072"="User logon to account disabled by administrator";
    "0XC00000DC"="Sam Server was in the wrong state to perform the desired operation.";
    "0XC0000133"="Clocks between DC and other computer too far out of sync";
    "0XC000015B"="The user has not been granted the requested logon type at this machine";
    "0XC000018C"="The logon request failed because the trust relationship between the primary domain and the trusted domain failed.";
    "0XC0000192"="An attempt was made to logon, but the Netlogon service was not started.";
    "0xC0000193"="User logon attempt with expired account.";
    "0XC0000224"="User is required to change password at next logon";
    "0XC0000225"="Evidently a bug in Windows and not a risk";
    "0xC0000234"="User logon attemot with account locked";
    "0XC00002EE"="Failure Reason: An Error occurred during Logon";
    "0XC0000413"="Logon Failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.";
    "0x0"="Status OK"
}

# XML Query Filter Boilerplate that can be exported to Event Viewer

$XmlQueryTemplate = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
       {0}
    </Select>
  </Query>
</QueryList>
'@

Function Get-WindowsAuditEvent {
    <#
    .SYNOPSIS
        Searches the Windows Security Event log on COMPUTER (parameter) for a list of security event ids
        Can be useful in troubleshooting ActiveDirectory Identity Sources
        
    .PARAMETER EventList
        A list (array) of Security event ids to search for. The default is events @(4624,4625,4776,4768,4769,4740)

    .PARAMETER RecentMinutes
        Allows events to be filtered from the last n minutes. The default is for events reported in the last 10 minutes 

    .PARAMETER Computer
        Specify a list of computers to search. The default is the local computer

        Example -Computer "ServerA,ServerB" will search ServerA and ServerB

    .PARAMETER IPAddress
        Search for a specific Source IP Address. This could be the Morpheus Appliance

    .PARAMETER TargetUser
        Search for a specific User SamAccountName. This could be the username being used to access Morpheus

    .PARAMETER AsXml
        Return a configured XML Query which can be pasted into Windows Event Viewer as an XML search filter
    
    .PARAMETER AsSummary
        Return a summary of matching events

    .PARAMETER AsJson
        Return the summary as a json object

    .OUTPUTS
        Matching Security Events in the format Requested (SecurityEvents, Summary, Summary json object or XML Query)

    #>     
    param (
        [int32[]]$EventList=@(4624,4625,4776,4768,4769,4740),
        [int32]$RecentMinutes = 10,
        [String]$Computer = "localhost",
        [String]$IPAddress,
        [String]$TargetUser,
        [Switch]$AsXML,
        [Switch]$AsSummary,
        [Switch]$AsJson
    )

    # If a list of Computers is passed as a parameter split these by ,
    $ComputerList = $Computer -Split "\s*,\s*"

    # Setup the xPath Query for fast filtering of EventLog

    $EventQuery = [String]::Join(" or ",$($EventList | Foreach-Object {"EventID=$_"}))
    Write-Verbose $EventQuery

    $TimeSpan = (New-TimeSpan -Minutes $RecentMinutes).TotalMilliseconds

    #Filter the Event\System Node for EventId's and TimeCreated 
    $xSysFilter = "TimeCreated[timediff(@SystemTime)&lt;={0}] and ({1})" -f $TimeSpan, $EventQuery

    if ($IPAddress -And $TargetUser) {
        $xEventDataFilter = "[EventData[Data[@Name='IPAddress']='{0}' or Data[@Name='TargetUserName']='{1}']]" -f $IPAddress, $TargetUser
    }
    elseif ($IPAddress) {
        #Filter the EventData node for <Data Name="Ipaddress">MorpheusIPAddress</Data>
        $xEventDataFilter = "[EventData[Data[@Name='IPAddress']='{0}']]" -f $IPAddress
    }
    elseif ($TargetUser) {
        #Filter the EventData node for <Data Name="Ipaddress">MorpheusIPAddress</Data>
        $xEventDataFilter = "[EventData[Data[@Name='TargetUserName']='{0}']]" -f $TargetUser
    }
    else {
        $xEventDataFilter = ""
    }
    
    # Construct the xPath filter
    $xPath = "Event[System[{0}]]{1}" -f $xSysFilter, $xEventDataFilter
    Write-Verbose "Using xPath Filter $($xPath)"
    $XmlQuery = $XmlQueryTemplate -f $xPath

    if ($AsXML) {
        Write-Host "AsXML Parameter: Returning XML Query Filter for use in Event Viewer ..." -ForegroundColor Green
        return $XmlQuery
    }

    # Get Events using the xPath filter

    $Events = $ComputerList | Foreach-Object {Get-WinEvent -ComputerName $_ -FilterXML $XmlQuery -ErrorAction SilentlyContinue}

    if ($Events) {
        if ($AsSummary -Or $AsJson) {           
            $Summary = foreach ($Event in $Events) {
                $EventData = Get-EventdataProperties -Event $Event
                [PSCustomObject]@{
                    #Audit            = if ($Event.Id -eq 4624) {"Success"} else {"Fail"};
                    RecordId         = $Event.RecordId;
                    TimeCreated      = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff");
                    Id               = $Event.Id;
                    MachineName      = $Event.MachineName;
                    TargetUserName   = $EventData.TargetUserName;
                    TargetDomainName = $EventData.TargetDomainName;
                    IpAddress        = $EventData.IpAddress;
                    IpPort           = $EventData.IpPort;
                    Status           = if ($Event.Id -eq 4625) {$Script:StatusCodes.Item($EventData.Status)} else {"-"};
                    SubStatus        = if ($Event.Id -eq 4625) {$Script:StatusCodes.Item($EventData.SubStatus)} else {"-"};
                    FailureReason    = if ($Event.Id -eq 4625) {$EventData.FailureReason} else {"-"};
                    EventData        = $EventData;
                }
            }
            if ($AsJson) {
                return $Summary | ConvertTo-Json -Depth 3
            } else {
                return $Summary
            }
        }
        else {
            return $Events
        }
    } else {
        Write-Warning "No Events match chosen criteria"
    }
} 


Function Get-WindowsRestartEvent {
    <#
    .SYNOPSIS
        Searches specified Computer for a recognised list of Computer Restart events
        
    .PARAMETER Computer
        Search for events on this computer. The default is the local computer

    .PARAMETER InLast
        Restricts the search for the last Hour,Day,Week or Month
        The default value is the last day

    .PARAMETER AsJson
        Return matchjinmg events in json format

    .OUTPUTS
        Matching Events in optional json format

    #>      
    [CmdletBinding()]
    param (
        [String]$Computer=$null,
        [ValidateSet("Hour","Day","Week","Month")]
        [String]$InLast="Day",
        [Switch]$AsJson
    )

    $now = Get-Date
    switch ($InLast) {
        "Hour" {$Start = $now.AddHours(-1)}
        "Day" {$Start = $now.AddDays(-1)}
        "Week" {$Start = $now.AddDays(-7)}
        "Month" {$Start = $now.AddMonths(-1)}
        default {$Start = $now.AddDays(-1)}
    }

    $EventProperties = @("RecordId",@{n="TimeCreated";e={$_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff")}},"Id","MachineName","Message")
    if ($Computer) {
        $reboot=Get-WinEvent -ErrorAction "SilentlyContinue" -Computer $Computer -FilterHashtable @{ID=@(41,6005,6006,6008,6009,6011,6013,1074,1076);logName="System";StartTime=$Start}
    } else {
        $reboot=Get-WinEvent -ErrorAction "SilentlyContinue" -FilterHashtable @{ID=@(41,6005,6006,6008,6009,6011,6013,1074,1076);logName="System";StartTime=$Start}
    }
    if ($AsJson) {
       return $Reboot | Select-Object -Property $EventProperties | ConvertTo-Json -depth 3
    } else {
       return $reboot | Select-Object -Property $EventProperties
    } 
}


Function XmlPrettyPrint {
    <#
    .SYNOPSIS
        Pretty format XML Sting

    .PARAMETER Xml
        A String object containing a well formed  XML Fragnment

    .OUTPUTS
        Formatted XML String

    #>  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Xml
    )

    # Read
    $stringReader = New-Object System.IO.StringReader($Xml)
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.CloseInput = $true
    $settings.IgnoreWhitespace = $true
    $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
   
    $stringWriter = New-Object System.IO.StringWriter
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.CloseOutput = $true
    $settings.Indent = $true
    $writer = [System.Xml.XmlWriter]::Create($stringWriter, $settings)
   
    while (!$reader.EOF) {
        $writer.WriteNode($reader, $false)
    }
    $writer.Flush()
   
    $result = $stringWriter.ToString()
    $reader.Close()
    $writer.Close()
    $result
}


Function Get-EventdataProperties {
    <#
    .SYNOPSIS
        Helper Function to return EventData properties from the Windows XML Security Event

    .PARAMETER Event
        Security Event

    .OUTPUTS
        PSCustomObject containing the Event Properties

    #>  
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$Event
    )

    Begin {
        $SecurityConstants = @{
            "%%1832" = "Identification";
            "%%1833" = "Impersonation";
            "%%1840" = "Delegation";
            "%%1841" = "Denied by Process Trust Label ACE";
            "%%1842" = "Yes";
            "%%1843" = "No";
            "%%1844" = "System";
            "%%1845" = "Not Available";
            "%%1846" = "Default";
            "%%1847" = "DisallowMmConfig";
            "%%1848" = "Off";
            "%%1849" = "Auto";
            "%%2305" = "The specified user account has expired.";
            "%%2309" = "The specified account password has expired.";
            "%%2310" = "Account currently disabled.";
            "%%2311" = "Account logon time restriction violation.";
            "%%2312" = "User not allowed to logon at this computer.";
            "%%2313" = "Unknown user name or bad password.";
            "%%2304" = "An Error occurred during Logon."
        }
        $EventData = [System.Collections.Generic.List[Object]]::new()
    }

    Process {
        foreach ($E in $Event) {
            $XMLString = $E.toXML()
            #Replace any Event %% tokens while in String format
            foreach ($K in $SecurityConstants.Keys) {
                $XMLString = $XMLString.Replace($k,$SecurityConstants.item($k))
            }
            [XML]$EventXML = $XMLString
            $EventProperties = [PSCustomObject]@{}
            if ($EventXML.Event.EventData) {
                $EventXML.Event.EventData.Data | 
                Foreach-Object { Add-Member -InputObject $EventProperties -MemberType NoteProperty -Name $_.name -Value $_.'#text' }
            }
            $EventData.Add($EventProperties)
        }
    }

    End {
        return $EventData
    }
}
Function Get-WindowsSetupEvents {
    <#
    .SYNOPSIS
        Read the Windows Setup event log file C:\Windows\Panther\setup.etl 
    .PARAMETER StartDate
        DateTime after which events will be resturned
    .PARAMETER AsJson
        Return results as Json string
    .OUTPUTS
        PSCustomObject containing the Event Properties

    #>  
    [CmdletBinding()]
    Param (
        [DateTime]$StartDate,
        $SetupLog="C:\Windows\Panther\Setup.etl",
        [Switch]$AsJson
    )    

    if (Test-Path $SetupLog) {
        if ($StartDate) {
            write-Host "Listing Setup events from $($StartDate)"
        } else {
           $StartDate = (Get-WindowsSetupDate).installDate.Date
           write-Host "Listing Setup events from Windows Install Date $($StartDate)"
        }

        $params = @{
            Path=$SetupLog;
            Oldest=$true
        }
        # filter out events with no Message - not at all useful
        $setup = Get-WinEvent @params | Where-Object {$_.TimeCreated -gt $StartDate -and $_.Message}
        if ($AsJson) {
            return $setup | Select-Object -Property RecordId, @{N="TimeCreated";E={$_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff")}}, Message | Convertto-Json 
        } else {
            return $setup | Select-Object -Property RecordId, TimeCreated, Message
        }
    } else {
        Write-Error "Cannot locate Windows Setup Log $($SetupLog)"
    }
}


Function Get-WindowsSetupDate{
    <#
    .SYNOPSIS
        Read the Windows Install Date from the Registry

    .PARAMETER Computer
        Read the InstallDate from a remote Computer
    .PARAMETER AsJson
        Return results as Json string
    .OUTPUTS
        DateTime when the Windows Installation completed

    #>
    [CmdletBinding()]
    param (
        [String]$Computer="",
        [Switch]$AsJson
    )
       

    $SB = {
        $installTime = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallTime").InstallTime
        $product = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName").ProductName
        $rtn=[PSCustomObject]@{
            computer=[Environment]::MachineName;
            product=$product;
            installDate = [DateTime]::FromFileTime($installTime)
            installDateUtc = [DateTime]::FromFileTimeUtc($installTime)
        }
        return $rtn
    }
    $params = @{
        ScriptBlock=$SB
    }
    if ($Computer) {
        $params.Add("Computer",$Computer)
        $params.Add("HideComputerName",$true)
    }
    $ret=Invoke-Command @params
    if ($AsJson) {
        $ret.installDate = $ret.installDate.ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $ret.installDateUtc = $ret.installDateUtc.ToString("yyyy-MM-ddTHH:mm:ss.fff")
        return $ret | Select-Object -Property computer, product, installDate, installDateUtc | Convertto-Json
    } else {
        return $ret
    }
    
}

Function Read-PSLog {
    <#
    .SYNOPSIS
        Reads the Windows Powershell logs and returns script executions. If the script is Base64 encoded then
        this script decodes and returns the actual powershell. Useful for reading any Morpheus WinRm RPC commands

    .PARAMETER EventId
        Event ID to read. Default is Event 403

    .PARAMETER Computer
        Computername. Default is local Computer

    .PARAMETER StartDate

    .OUTPUTS
        DateTime when the Windows Installation completed

    #>
    [CmdletBinding()]    
    param (
        $EventId=403,
        [String]$Computer=$null,
        [DateTime]$StartDate,
        [Switch]$AsJson
    )

    #Default to Setup Date if no StartDate
    if (-Not $StartDate) {
        $StartDate = (Get-WindowsSetupDate).installDate.Date
    }
    $Filter = @{LogName="Windows Powershell";Id=$EventId;StartTime=$StartDate}

    $Events = Get-WinEvent -FilterHashtable $Filter | Sort-Object -Property RecordId

    $eventData = foreach ($e in $Events) {
        $output = [PSCustomObject]@{
            computer=$e.MachineName;
            index=$e.RecordId;
            Time=$e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff");
            host="";
            command="";
            encodedcommand=""
        }
        
        if ($e.message -match "HostName=(.*)\r") {
            $output.host=$matches[1]
        }
        if ($e.message -match "HostApplication=(.*)\r") {
            $output.command=$matches[1]
            if ($output.command -match "-encodedcommand (\S*)") {
                #Base64 encoded command
                $output.encodedcommand=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($matches[1]))
            }
        }
        $output
    }
    if ($AsJson) {
        return $eventData | ConvertTo-Json -Depth 3 
    } else {
        return $eventData
    }    
}


