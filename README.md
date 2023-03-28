# EDR_Process_Grapher
Takes various input from EDR tools and attempts to create a visual process graph.  Can be used to support multiple outputs - however there are some required fields that will need to be in the output (see conigs).

#Usage
Runs OS independent - requires PowerShell. Run the script by providing the following CLI:

./prog_grapher.ps1 -C ./configs/mdatp.json -I ./mdatp_export_logs.csv -O ./html/graph.json

Please note - the script outputs the json file listing in the Output parameter - this is what is read by the D3 Javascript in the html directory.  The graph.json produced needs to exist in the same directory as html/javascript.

The HTML needs to be hosted by a webserver; you can do this by running a python simple server:

# python3 -m http.server 8000

Then navigate in your browser to:

http://127.0.0.1:8000/proc.html

#Results
![Screenshot_20230328_135140](https://user-images.githubusercontent.com/32649378/228326069-28bc5bca-5632-4e21-900c-e9278e03fff8.png)

