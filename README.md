# WindowsSecEvents

Powershell Function for querying Morpheus Related Windows Security Events while troubleshooting AD Identity Sources.

To load the script Dot Source the WindowsSecEvents.ps1 file into a powershell session

```
PS> . .\WindowsSecEvents.ps1
```

**NOTE** to run these Powershell Scripts the account must be and Administrator with access to query the Security Event log on the target computer. When querying the Domain Controller Security log the user will most likely be a Domain Admin.

## Loading Directly from GitHub URL

It is possible to load these Functions directly from GitHub if your Endpoint has an Internet connection. Use the following  Powershell to download and Install a Dynamic Module directly from a GitHub Url

```
$Uri = "https://raw.githubusercontent.com/spottsmorpheus/WindowsSecEvents/main/src/WindowsSecEvents.ps1"
$ProgressPreference = "SilentlyContinue"
# Load Powershell code from GitHub Uri and invoke as a temporary Module
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
if ($Response.StatusCode -eq 200) {
    $Module = New-Module -Name "WindowsSecEvents" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
}
```

## About the Functions

### Get-WindowsAuditEvents

```
NAME
    Get-WindowsAuditEvents

SYNOPSIS
    Searches the Windows Security Event log on COMPUTER (parameter) for a list of security event ids
    Can be useful in troubleshooting ActiveDirectory Identity Sources


SYNTAX
    Get-WindowsAuditEvents [[-EventList] <Int32[]>] [[-RecentMinutes] <Int32>] [[-Computer] <String>]
    [[-IPAddress] <String>] [[-TargetUser] <String>] [-AsXML] [-AsSummary] [-AsJson] [<CommonParameters>]


DESCRIPTION


PARAMETERS
    -EventList <Int32[]>
        A list (array) of Security event ids to search for. The default is events @(4624,4625,4776,4768,4769)

    -RecentMinutes <Int32>
        Allows events to be filtered from the last n minutes. The default is for events reported in the last 10 minutes

    -Computer <String>
        Specify a list of computers to search. The default is the local computer

        Example -Computer "ServerA,ServerB" will search ServerA and ServerB

    -IPAddress <String>
        Search for a specific Source IP Address. This could be the Morpheus Appliance

    -TargetUser <String>
        Search for a specific User SamAccountName. This could be the username being used to access Morpheus

    -AsXML [<SwitchParameter>]
        Return a configured XML Query which can be pasted into Windows Event Viewer as an XML search filter

    -AsSummary [<SwitchParameter>]
        Return a summary of matching events

    -AsJson [<SwitchParameter>]
        Return the summary as a json object

```

### Get-WindowsRestartEvent

```
NAME
    Get-WindowsRestartEvent

SYNOPSIS
    Searches specified Computer for a recognised list of Computer Restart events


SYNTAX
    Get-WindowsRestartEvent [[-Computer] <String>] [[-InLast] <String>] [-AsJson] [<CommonParameters>]


DESCRIPTION


PARAMETERS
    -Computer <String>
        Search for events on this computer. The default is the local computer

    -InLast <String>
        Restricts the search for the last Hour,Day,Week or Month
        The default value is the last day

    -AsJson [<SwitchParameter>]
        Return matchjinmg events in json format
```


### Generating an XML Search filter

**Get-WindowsAuditEvents** can be used to generate XML which can be used directly in Event Viewer. As an example

```
Get-WindowsAuditEvents -Recent 3 -IPAddress "10.10.10.10" -TargetUser "spotts" -AsXML

Using XML Query Filter: Paste this filter into Event Viewer to view events

<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
       Event[System[TimeCreated[timediff(@SystemTime)&lt;=180000] and (EventID=4624 or EventID=4625 or EventID=4776 or EventID=4768 or EventID=4769)]][EventData[Data[@Name='IPAddress']='10.10.10.10' or Data[@Name='TargetUserName']='spotts']]
    </Select>
  </Query>
</QueryList>
```

- Copy the XML output by the Powershell Function
- Open Event Viewer. From the Actions menu select Filter current Log.
- Select the XML tab.
- Check the **Edit query manually** checkbox. Click Yes to acknowledge the warning
- Clear the current contents and paste in the XML output from the Powershell function
- Click OK

Refresh the Event Viewer to see the latest events matching the filter

## Significant Event Ids

### Login Success Event 4624

To check for a successful login on Domain Controller MYDC01 by user morphuser in the last 5 minutes returning results as json

```
Get-WindowsAuditEvents -Recent 5 -Computer "MYDC01" -TargetUser "morphuser" -Eventlist @(4624) -AsJson
```

### Login Failure Event 4625

To check for login failures on Domain Controller MYDC01 from appliance 10.10.10.10 in the last 20 minutes returning results as json

In this example below the check the Status,SubStatus and FailureReason. In this example the accounts password must be changed on the next login preventing the account logging into Morpheus

```
Get-WindowsAuditEvents -Recent 20 -Computer "MYDC01" -IPAddress "10.10.10.10" -Eventlist @(4625) -AsJson
{
    "RecordId":  51599589,
    "TimeCreated":  "2023-09-21T00:54:10.668",
    "Id":  4625,
    "MachineName":  "MYDC01.example.com",
    "TargetUserName":  "morphuser1",
    "TargetDomainName":  "TEST",
    "IpAddress":  "10.10.10.10",
    "IpPort":  "37372",
    "Status":  "User is required to change password at next logon",
    "SubStatus":  "Status OK",
    "FailureReason":  "The specified account password has expired.",
    "EventData":  {
                      "SubjectUserSid":  "S-1-5-18",
                      "SubjectUserName":  "MYDC01$",
                      "SubjectDomainName":  "EXAMPLE",
                      "SubjectLogonId":  "0x3e7",
                      "TargetUserSid":  "S-1-0-0",
                      "TargetUserName":  "morphuser1",
                      "TargetDomainName":  "EXAMPLE",
                      "Status":  "0xc0000224",
                      "FailureReason":  "The specified account password has expired.",
                      "SubStatus":  "0x0",
                      "LogonType":  "3",
                      "LogonProcessName":  "Advapi  ",
                      "AuthenticationPackageName":  "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
                      "WorkstationName":  "MYDC01",
                      "TransmittedServices":  "-",
                      "LmPackageName":  "-",
                      "KeyLength":  "0",
                      "ProcessId":  "0x298",
                      "ProcessName":  "C:\\Windows\\System32\\lsass.exe",
                      "IpAddress":  "10.10.10.10",
                      "IpPort":  "37372"
                  }
}
```
