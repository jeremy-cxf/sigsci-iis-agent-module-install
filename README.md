### Signal Sciences Module / Agent Powershell Install for Windows
----

Usage:
```powershell
./install-sigsci-agent-module-iis.ps1 -modversion latest -agentversion latest -accesskeyid <youraccesskey> -secretaccesskey <secretaccesskey>
```

Args:
- modversion [required]
- agentversion [required]
- accesskeyid [optional]
- secretaccesskey [optional]

This tool will do the following:
- Install the agent  (version specified)
- Install the module (version specified)
- Install IIS if not installed.

If a secretaccesskey and accesskeyid are not provided, it will install, but the agent cannot bootstrap to log to the control plane or provide advice to the module for requests.

I will update this from time to time when I have the time. 
I am bad at powershell and it shows :) 

NOTE
***This is not an official way to install the agent nor module.
I uplodated this as this is how I deploy my dev instances.***
