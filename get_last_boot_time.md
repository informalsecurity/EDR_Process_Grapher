Getting the last boot time makes the process graph work better (IE - it will include all process start events all the way up the chain) and make a better process graph.  You should TRY to export all events from the last boot time before the event in question
## Crowdstrike
---------------------------------------------
```
#event_simpleName=AgentOnline
| ComputerName=/(YOUR_COMPUTER_NAME_HERE)/i
| groupBy(ComputerName, function=max(@timestamp, as=LastBootTime))
| LastBootTime := formatTime(field=LastBootTime, format="%Y-%m-%d %H:%M:%S")
```

## Defender ATP (KQL Query)
---------------------------------------------
```
DeviceInfo
| where DeviceName == "YOUR_COMPUTER_NAME_HERE"
| summarize LastBootTime = max(Timestamp) by DeviceName

```
OR
```
DeviceEvents
| where DeviceName == "YOUR_COMPUTER_NAME_HERE"
| where ActionType == "OsStarted"
| summarize LastBootTime = max(Timestamp) by DeviceName
```
OR
```
DeviceEvents
| where ActionType == "OsStarted"
| where DeviceName == "YOUR_COMPUTER_NAME_HERE"
| top 1 by Timestamp desc
| project DeviceName, LastBootTime = Timestamp
```
