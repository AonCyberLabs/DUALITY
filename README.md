<p align="center">
<img src="https://github.com/AonCyberLabs/DUALITY/blob/main/duality_logo_new.png" width="666" />
</p>

# DUALITY
This DUALITY engine accompanies the blog post. There are three parts.
- The C# DUALITY code which should be compiled by the user. You will need to install PeNet (via NuGet for example ```NuGet\Install-Package PeNet -Version 3.0.0```). There is a packages.config for your convenience.
- The "VM Assistant" scripts, which are inside the DUALITY folder. These scripts will run on some Windows 10 assistant VM that should be open only to the machine running your Cobalt Strike GUI. **Do not connect this assistant VM to the internet.**
- The aggressor script (DUALITY.cna)

### C# DUALITY Code
DUALITY assumes that the current user running the tool is the "Administrator" user. If that's not the case, change the user in Program.cs in the DUALITY folder.
You may also have to adjust the location of cl.exe and ml64.exe, nameley these lines:
```
var envBatPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat";
var clPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.34.31933\bin\Hostx64\x64\cl.exe";
var mlPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.34.31933\bin\Hostx64\x64\ml64.exe";
var masmshcPath = @"C:\Users\Administrator\source\repos\DUALITY\DUALITY\masm_shc.exe";
var sccPath = @"C:\Users\Administrator\source\repos\DUALITY\DUALITY\scc.cpp";
```
Just make sure these point to programs that are in the right place for your setup. MSVC\14.34.31933 might need to point to somewhere else. I may put these strings in a config file down the line, but for now, run through the whole pipeline at least once to ensure everything is interconnected properly.

DUALITY depends on masm_shc.exe. It's included in this repo, but if you want to download / build your own version, grab it from here: https://github.com/hasherezade/masm_shc

### VM Assistant Scripts
There is a README inside the "assistant_VM_scripts" folder. Follow the instructions there to get your VM and the scripts set up.

### Aggressor script (DUALITY.cna)
DUALITY.cna uses a pre-populated list of target DLLs to look for when you run the script, in the process of trying to backdoor them. If you don't know what to expect, that's fine - after you get a shell, update this list in the aggressor script to what you're interested in backdooring, then reload the aggressor script in the Cobalt Strike GUI. Then run DUALITY again. UNDUALITY will use the same list FYI. Note the usage of "SOMEDUALITYUSER" as the placeholder for the username. Make sure you follow that naming scheme.

Another thing in the aggressor script - make sure you adjust the URL to the assistant VM. This is going to be this line:
```$weburl = "http://192.168.69.33";```
Lastly, ensure that the hardcoded paths to inbuilt binaries such as mv, curl and wget are accurate.
Change that to the IP address of your assistant VM. Make sure your Windows machine firewall is off for the network context you're in (or open a port, up to you). Again, **do not connect this assistant VM to the internet. You might get pwned.**

### Copyright

Copyright 2024 Aon plc
