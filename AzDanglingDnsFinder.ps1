# Read DNS Names from file  
$dnsNames = Get-Content -Path .\domainnames.txt  
  
# Get the current Azure subscription context  
$currentContext = Get-AzContext  
  
# Extract the Subscription ID from the context  
$subscriptionId = $currentContext.Subscription.Id  
  
function Get-AccesTokenFromCurrentUser {  
    $azContext = Get-AzContext  
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile  
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList $azProfile  
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)  
    ('Bearer ' + $token.AccessToken)  
}  
  
$AuthorizationToken = Get-AccesTokenFromCurrentUser  
  
# Check name availability function  
function Check-AzNameAvailability {  
    param(  
        [Parameter(Mandatory = $true)] [string] $AuthorizationToken,  
        [Parameter(Mandatory = $true)] [string] $SubscriptionId,  
        [Parameter(Mandatory = $true)] [string] $Name,  
        [Parameter(Mandatory = $true)] [ValidateSet(  
            'ApiManagement', 'WebApp', 'FrontDoor', 'TrafficManager')]  
        $ServiceType  
    )  
   
    # Define URIs and types for each service type  
    $uriByServiceType = @{  
        ApiManagement   = 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/checkNameAvailability?api-version=2019-01-01'  
        WebApp          = 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Web/checknameavailability?api-version=2022-03-01'  
        FrontDoor       = 'https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/checkEndpointNameAvailability?api-version=2023-05-01'  
        TrafficManager  = 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/checkTrafficManagerNameAvailabilityV2?api-version=2022-04-01'  
    }  
   
    $typeByServiceType = @{  
        ApiManagement   = 'Microsoft.ApiManagement/service'  
        WebApp          = 'Microsoft.Web/sites'  
        FrontDoor       = 'Microsoft.Cdn/Profiles/AfdEndpoints'  
        TrafficManager  = 'Microsoft.Network/trafficmanagerprofiles'  
    }  
   
    # Prepare URI and body for the request  
    $uri = $uriByServiceType[$ServiceType] -replace ([regex]::Escape('{subscriptionId}')), $SubscriptionId  
    $body = '"name": "{0}", "type": "{1}"' -f $Name, $typeByServiceType[$ServiceType]  
   
    # Send the request  
    $response = (Invoke-WebRequest -Uri $uri -Method Post -Body "{$body}" -ContentType "application/json" -Headers @{Authorization = $AuthorizationToken }).content  
    $response | ConvertFrom-Json |  
        Select-Object @{N = 'Name'; E = { $Name } }, @{N = 'Type'; E = { $ServiceType } }, @{N = 'Available'; E = { $_ | Select-Object -ExpandProperty *available } }, Reason, Message  
}
  
# Iterate over each DNS Name  
foreach ($dnsName in $dnsNames) {  
    # Resolve DNS Name  
    $resolved = Resolve-DnsName -Name $dnsName -Type CNAME -ErrorAction SilentlyContinue  
  
    # Check if resolution was successful  
    if ($null -ne $resolved) {  
        # Check if resolved CNAME Record matches any of the Azure services  
        if ($resolved.NameHost -match "\.azure-api\.net$|\.azurewebsites\.net$|\.trafficmanager\.net$|\.azurefd\.net$|\.cloudapp\.azure\.com$") {  
            # Extract the Azure Record Name  
            $azureRecordName = $resolved.NameHost  
  
            # Output that DNS Name resolves to an Azure Record  
            Write-Host "$dnsName resolves to an Azure record - $azureRecordName"  
  
            # Determine the Service Type  
            switch -Regex ($azureRecordName) {  
                "\.azure-api\.net$" { $serviceType = 'ApiManagement' }  
                "\.azurewebsites\.net$" { $serviceType = 'WebApp' }  
                "\.trafficmanager\.net$" { $serviceType = 'TrafficManager' }  
                "\.azurefd\.net$" { $serviceType = 'FrontDoor' }  
                "\.cloudapp\.azure\.com$" { $serviceType = 'PublicIP' }  
            }  
  
            # Extract the Record Name and Location (if applicable)  
            $recordName = $azureRecordName.Split('.')[0]  
            if ($serviceType -eq 'PublicIP') {  
                $recordLocation = $azureRecordName.Split('.')[1]  
            }  
  
            # Check for Availability  
            if ($serviceType -eq 'PublicIP') {  
                # For PublicIP, use the Az module's Test-AzDnsAvailability cmdlet  
                $availability = Test-AzDnsAvailability -DomainNameLabel $recordName -Location $recordLocation  
                if ($availability) {  
                    Write-Host -ForegroundColor Red "DANGLING DNS with record name $recordName detected for service $serviceType in $recordLocation - Vulnerable to sub-domain takeover"  
                } else {  
                    Write-Host "Record not vulnerable to sub-domain takeover"  
                }  
            } else {  
                # For other Service Types, use the Check-AzNameAvailability function  
                $availability = Check-AzNameAvailability -AuthorizationToken $AuthorizationToken -SubscriptionId $subscriptionId -Name $recordName -ServiceType $serviceType  
                if ($availability.Available) {  
                    Write-Host -ForegroundColor Red "DANGLING DNS with record name $recordName detected for service $serviceType - Vulnerable to sub-domain takeover"  
                } else {  
                    Write-Host "Record not vulnerable to sub-domain takeover"  
                }  
            }  
        } else {  
            # Output that DNS Name does not resolve to an Azure Record  
            Write-Host "$dnsName does not resolve to an Azure record"  
        }  
    } else {  
        # Output that DNS Name could not be resolved  
        Write-Host "$dnsName could not be resolved"  
    }  
}