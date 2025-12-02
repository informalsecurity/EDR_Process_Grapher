# EDR_Process_Grapher
Takes SYSMON events (already converted into a JSON format) and attempts to create a visual process graph. 

# Usage
Runs OS independent - requires PowerShell. Run the script by providing the following CLI:
```
./proc_grapher.ps1
```
You will be prompted for a directory that contains all the SYSMON JSON exports you want to convert/

# Output
A new JSON file with the system name as the file name will be created in the same directory the SYSMON JSON inputs are.

# How to use
The HTML needs to be hosted by a webserver; you can do this by running a python simple server:
```
python3 -m http.server 8000
```
Then navigate in your browser to:

http://127.0.0.1:8000/process_grapher.html

Load the created JSON file from the PowerShell script into the web page  by clicking on "Choose File"

# Results
## REVIEW DETAILED PROCESS DETAILS
Select a process to reveal info, including unique network connections, DNS requests, Command Line, Files Dropped, and Rules/Techniques detected by SYSMON
<img width="1078" height="855" alt="image" src="https://github.com/user-attachments/assets/2da491de-0a36-4504-a66b-3ace21bc092c" />
Processes are decorated with icons to indicate interesting items:
LIGHTNING - Indicates possible Process Injection
FILE - Indicated files were created by this process
RED BOX - Indicates Network Connections
MAGNIFYING GLASS - Indicated DNS Resolutions

## HIGHLIGHT MALICIOUS PROCESSES
Use the mark as Malicious Button to highlight process trees known to be malicious
<img width="1188" height="775" alt="image" src="https://github.com/user-attachments/assets/bfc75133-0f62-4722-8468-8039c10199ad" />

## CONNECTION MODE
Hit CTRL+ALT to enter connection mode when injection between processes are identified.  Use the buttons on the Bottom left to clear connections if needed:
<img width="1197" height="867" alt="image" src="https://github.com/user-attachments/assets/550bf19b-beec-4698-bada-cd796109878a" />


# Work In Progress!!!!
To Do:
* Parameterize inputs/outputs
* Add additional EDR (Crowdstrike, Defender ATP, S1, etc.)
