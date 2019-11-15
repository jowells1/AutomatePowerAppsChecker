# AutomatePowerAppsChecker
Automate the creation of an Azure AD App registration required for PowerApps Checker and then automate the processing of solution analysis via PowerShell

CreateAzureAppReg.ps1 
  .SYNOPSIS
      Creates an Azure AD App registration necessary for PowerApps Checker  

  .DESCRIPTION
      This script will create an Azure AD App registration within the tenant of the user that is entering in their credentials. The user that enters in their credentials to this script must have the ability to create Azure AD app registrations and secrets.

  .NOTES
      File Name: CreateAzureAppReg.ps1
      Author: Grant Geiszler and Josh Wells
      Contributions by: https://nishantrana.me/2019/07/12/using-the-powerapps-checker-powershell-module-to-validate-the-solution/
      More Information: https://powerapps.microsoft.com/en-us/blog/automatically-validate-your-solutions-using-the-powerapps-checker-powershell-module/

- Requirements:
  Azure Active Directory
  User with permissions to create Azure AD App registration: https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles

AnalyzeSolutionsWithSolutionChecker.ps1
  .SYNOPSIS
      Export all unmanaged solutions from a CDS instance and then submit those files to PowerApps Checker for analysis.  

  .DESCRIPTION
      This script will download all unmanaged solutions, except the Default Solution, from a CDS instance to a local directory (defined in $solutionDirectory), submit the solutions to PowerApps Checker for analysis, extract the SARIF results, and outputs the final results in a CSV file

  .NOTES
      File Name: AnalyzeSolutionsWithSolutionChecker.ps1
      Author: Grant Geiszler and Josh Wells
      Contributions by: Bryan Newman
      Credits to: Nishant Rana - https://nishantrana.me/2019/07/12/using-the-powerapps-checker-powershell-module-to-validate-the-solution/
      More Information: https://powerapps.microsoft.com/en-us/blog/automatically-validate-your-solutions-using-the-powerapps-checker-powershell-module/
      
  - Requirements:
    User who runs the script must be a Dynamics CRM/365 or Common Data Service System Administrator or Customizer Administrator
