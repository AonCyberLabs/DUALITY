### Setup Instructions

On the assistant Windows VM:
- Do everything as admin.
- Make sure your firewall is off / configured to talk to your Cobalt Strike host.
- Also make sure Windows Defender is entirely disabled / removed. You can use this tool: https://github.com/qtkite/defender-control/releases/tag/v1.5
- Install Python 3 on the system.
- Install Visual Studio Community 2022, we're going to use cmake. Follow whatever prompts to make VS happy.
- Clone in the whole DUALITY github repo. Use the same path sequence that VS usually uses "C:\users\Administrator\source\repos\DUALITY".
- From the "assistant_VM_scripts" folder, copy "dualityserve.py" and "dualityTimed.py" to the Admin desktop.
- In a CMD prompt, CD to the admin desktop, run: ```python pythonWebServerWithUpload.py 80```
- In another CMD prompt, CD to the admin desktop, run: ```python dualityTimed.py```
- In your CNA script, change: 
```$weburl = "http://192.168.69.33";```
to wherever your assistant VM is.

### Copyright

Copyright 2024 Aon plc
