# AzDanglingDnsFinder
AzDanglingDnsFinder is a PowerShell script designed to identify DNS names that may be vulnerable to sub-domain takeover by checking if they point to Azure services that no longer exist or are not currently in use. The tool checks for dangling DNS records associated with Azure services like ApiManagement, WebApp, FrontDoor, and TrafficManager.

## Features
* Reads a list of DNS names from a file.
* Determines if DNS names resolve to Azure service records.
* Checks if the resolved Azure service names are available.
* Identifies potential vulnerabilities for sub-domain takeover.

## Supported Services
* ApiManagement
* WebApp
* FrontDoor
* TrafficManager

## Future Plans
* Extend support to additional Azure services.

## Prerequisites
* Azure PowerShell Module (Az module)
* Logged-in Azure account with appropriate permissions

## Installation
To install AzDanglingDnsFinder, perform the following steps:
1. Ensure Azure PowerShell is installed and authenticated (needed only for the necessary authenticated API calls)
```
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```
2. Download the AzDanglingDnsFinder.ps1 script to your local system.
3. Create a **`domainnames.txt`** file containing one DNS name per line.
4. Place the **`domainnames.txt`** file in the same directory as the **`AzDanglingDnsFinder.ps1`** script.
5. Execute the script:
```
.\AzDanglingDnsFinder.ps1
```

## Output
For each DNS name, the script outputs:
* Whether it resolves to an Azure service record.
* If it is potentially vulnerable to a sub-domain takeover.

## Contributing
We welcome contributions that enhance the functionality of AzDanglingDnsFinder. Please submit your contributions as pull requests on GitHub and ensure that your code adheres to the project's coding standards.
