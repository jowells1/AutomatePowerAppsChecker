# AutomatePowerAppsChecker

Automate the creation of an Azure AD App registration required for PowerApps Checker and then automate the processing of solution analysis via PowerShell.  

**Applies to**:

- Dynamics CRM 2016
- Dynamics 365 v8
- Dynamics 365 v9
- Common Data Service

## CreateAzureAppReg.ps1

This script will create an Azure AD App registration within the tenant of the user that is entering in their credentials. The output will give you the three necessary parameters for PowerApps Checker:

- TenantId
- ClientApplicationId
- ClientApplicationSecret

### Requirements

- The user that enters in their credentials to this script must have the ability to create Azure AD app registrations and secrets.
    - For more information, see: [Administrator role permissions in Azure Active Directory](https://docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-admin-roles)
- PowerShell x64 is required to use correct AzureAD modules
- PowerShell should not run as admin
- NuGet provider version 2.8.5.201, or greater, is required.

## AnalyzeSolutionsWithSolutionChecker.ps1

This script will download all unmanaged solutions, except the Default Solution, from a CDS instance to a local directory, submit the solutions to PowerApps Checker for analysis, extract the SARIF results, and outputs the final results in a CSV file

NOTE: Default and managed solutions are not supported for exporting.  
- For more information, see: [Export solutions](https://docs.microsoft.com/powerapps/maker/common-data-service/import-update-export-solutions#export-solutions)

### Requirements

- User who runs the script must be a Dynamics CRM/365 or Common Data Service System Administrator or Customizer Administrator
- PowerShell x64 is required to use correct AzureAD modules
- PowerShell should not run as admin
- NuGet provider version 2.8.5.201, or greater, is required.

## More Information

- [Using the PowerApps checker PowerShell Module to validate the solution](https://nishantrana.me/2019/07/12/using-the-powerapps-checker-powershell-module-to-validate-the-solution/) <br>
- [Automatically validate your solutions using the PowerApps checker PowerShell Module](https://powerapps.microsoft.com/blog/automatically-validate-your-solutions-using-the-powerapps-checker-powershell-module/) <br>
