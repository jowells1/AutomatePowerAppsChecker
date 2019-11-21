#*******************************************************************************************************
#                     Create Azure AD App for PowerApps Checker
#*******************************************************************************************************

<#
    
    .SYNOPSIS
        Creates an Azure AD App registration necessary for PowerApps Checker  

    .DESCRIPTION
        This script will create an Azure AD App registration within the tenant of the user that is entering in their credentials. The user that enters in their credentials to this script must have the ability to create Azure AD app registrations and secrets.
    
    .NOTES
        File Name: CreateAzureAppReg.ps1
        Author: Grant Geiszler and Josh Wells
        Contributions by: https://nishantrana.me/2019/07/12/using-the-powerapps-checker-powershell-module-to-validate-the-solution/
        More Information: https://powerapps.microsoft.com/en-us/blog/automatically-validate-your-solutions-using-the-powerapps-checker-powershell-module/
 
 #>


# Check to see if the AzureAD module exists to extract solutions from instance. If so, import it.  Otherwise, install it.
if (Get-Module -ListAvailable -Name AzureAD){
        Import-Module AzureAD
}
else {
        Install-Module AzureAD -Scope CurrentUser
}

Clear-Host

# Connect to Azure Services and push it to a variable
$azure = Connect-AzureAD

# Use date variable for the Azure AD AppName
$date = Get-Date

# Define the necessary parameters for the Azure AD App
$appName = ("{0}{1}" -f "PowerAppsChecker_", $date)
$replyURL = "urn:ietf:wg:oauth:2.0:oob"

# Get the PowerApps Advisor API object and Oauth2Permissions
$pAppsAdvisor = Get-AzureADServicePrincipal -Filter "DisplayName eq 'PowerApps-Advisor'"
$permission = $pAppsAdvisor.AppRoles | ? { $_.Value -match "Analysis.All" }

# Check to see if the App exists before creating it
if(!($myApp = Get-AzureADApplication -Filter "DisplayName eq '$($appName)'"  -ErrorAction SilentlyContinue))
{
    try
    {
        #Adding PowerApps Advisor API Oauth2permissions to the newly created app
        $requiredResources = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        
        ##Application Permissions
        $appPermission = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id,"Role"

        $requiredResources.ResourceAppId = $pAppsAdvisor.AppId
        $requiredResources.ResourceAccess = $appPermission

        # Creates AzureADApp for PowerAppsChecker
        $myApp = New-AzureADApplication -DisplayName $appName -ReplyUrls $replyURL -RequiredResourceAccess $requiredResources
        
        # Define the parameters for the App Client Secret
        $startDate = Get-Date
        $endDate = $startDate.AddYears(1)

        # Create the Client Secret
        $aadAppKeyPwd = New-AzureADApplicationPasswordCredential -ObjectId $myApp.ObjectId -CustomKeyIdentifier "Primary" -StartDate $startDate -EndDate $endDate

        # Output the necessary fields needed for PowerApps Checker
        #Clear-Host
        Write-Output ("{0}{1}" -f "TenantId: ", $azure.TenantId)
        Write-Output ("{0}{1}" -f "ClientApplicationId: ", $myApp.AppId)
        Write-Output ("{0}{1}" -f "ClientApplicationSecret: ", $aadAppKeyPwd.Value)
    }
    Catch
    {
        throw $_
    }
}
Else
{
    Write-Warning "App already exists"
    Break
}







