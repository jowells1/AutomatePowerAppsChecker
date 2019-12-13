Set-ExecutionPolicy –ExecutionPolicy RemoteSigned –Scope CurrentUser

#*******************************************************************************************************
#            Retrieve all Unmanaged Solutions from CDS and Analyze with PowerApps Checker
#*******************************************************************************************************

<#
    .SYNOPSIS
        Export all unmanaged solutions from a CDS instance and then submit those files to PowerApps Checker for analysis.  

    .DESCRIPTION
        This script will download all unmanaged solutions, except the Default Solution, from a CDS instance to a local directory (defined in $solutionDirectory), submit the solutions to PowerApps Checker for analysis, extract the SARIF results, and outputs the final results in a CSV file
    
    .NOTES
        File Name: AnalyzeSolutionsWithSolutionChecker.ps1
        Author: Grant Geiszler and Josh Wells
        Contributions by: Bryan Newman
        Credits to: Nishant Rana - https://nishantrana.me/2019/07/12/using-the-powerapps-checker-powershell-module-to-validate-the-solution/
        More Information:   https://powerapps.microsoft.com/en-us/blog/automatically-validate-your-solutions-using-the-powerapps-checker-powershell-module/
                            https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-powershell
 #>

 #****************Install or Import the Various Required Modules****************

# Check to see if the Xrm.Data module exists to export solutions from the instance. If so, import it.  Otherwise, install it.
if (Get-Module -ListAvailable -Name Microsoft.Xrm.Data.Powershell){
    Import-Module Microsoft.Xrm.Data.Powershell
}
else {
    Install-Module Microsoft.Xrm.Data.Powershell -AllowClobber -Scope CurrentUser
    Import-Module Microsoft.Xrm.Data.Powershell
}

# Check to see if the PowerApps.Checker module exists to analyze the exported solutions from the instance. If so, import it.  Otherwise, install it.
if (Get-Module -ListAvailable -Name Microsoft.PowerApps.Checker.Powershell){
    Import-Module Microsoft.PowerApps.Checker.Powershell
}
else {
    Install-Module -Name Microsoft.PowerApps.Checker.Powershell -AllowClobber -Scope CurrentUser
    Import-Module Microsoft.PowerApps.Checker.Powershell
}

# Check to see if the Azure Powershell module exists to add a solution to Azure blob. If so, import it.  Otherwise, install it.
if (Get-Module -ListAvailable -Name Az){
    Import-Module Az
}
else {
    Install-Module Az -AllowClobber -Scope CurrentUser
}

#/****************Install or Import the Various Required Modules****************

#****************File Variables****************

# Location to store and retrieve the solution files and add analysis folder
# $solutionsDirectory = "DRIVE:\FOLDER"
Clear-Host
Write-Host "Enter in an existing directory (full path) to download solutions and results to (DRIVE:\FOLDER)"
$solutionsDirectory = Read-Host "Working Directory"

# Check to see if the folder is a full directory path.  If not, then fail out
If($solutionsDirectory -match '([A-Z]:\\)')
{
    # Directory is a full directory path, continue on
}
Else
{
    Write-Warning "Enter in a full directory path.  Expected format is DRIVE:\FOLDER"
    Break
}

#/****************File Variables****************

#****************Retrieve Solution Variables****************

# Organization where Solutions are installed
# $crmUrl = "Instance URL (https://INSTANCE.crm.dynamics.com"
Clear-Host

#Validate if they want to retrieve a solution from CDS/D365 or simply analyze existing solution files in a folder
$existingFiles = Read-Host "Do you want to analyze existing files? (y/n)"

# Only keep the first character and put it to lower
$existingFiles = ($existingFiles.Substring(0,1)).ToLower()
            
# If yes, then skip connectivity prompts 
If($existingFiles -eq "y")
{

}
Else
{
    # Need to determine if it's an online or an on-premises environment so we connect and authenticate properly
    $deploymentOption = @{1 ="Online"; 2 = "On-premises"}
    Write-Host "Is your Dynamics CRM/365 or PowerApps instance online or on-premises"
    $deploymentOption | Sort-Object Name | Format-Table
    $deploymentInt = Read-Host "Enter the number of the appropriate deployment option (1 or 2)"

    #Check to if it's numeric and a 1 or 2.
    If($deploymentInt -match '[A-z]')
    {
        Write-Warning "Only enter the numeric value for the Geo"
        Break
    }
    Elseif (-not ($deploymentInt -match '\b([1-2])\b'))
    {
        Write-Warning "Only values 1-2 are expected"
        Break
    }
    Else # Need to validate the URL format is expected
    {
        Clear-Host
        # Ask for the full instance URL
        Write-Host "Instance URL should include the whole URL. Example: https://INSTANCE.crm.dynamics.com"
        $crmUrl = Read-Host "Instance URL (https://INSTANCE.crm.dynamics.com)"

        # Validate the proper URL format based on the deployment type.  If it's online, it should be https and ends in dynamics.com.  If it's on-premises, just need to validate that it's prefixed with http(s)://
        If($deploymentInt -eq 1)
        {
            # Check to see if the folder is a full directory path.  If not, then fail out
            If($crmUrl -match 'https://.*.dynamics.com')
            {
                # Instance URL is the full URL, continue on
            }
            Else
            {
                Write-Warning "Enter the full instance URL.  Expected format is https://INSTANCE.crm.dynamics.com"
                Break
            }
        }
        Else
        {
            # Check to see if the folder is a full directory path.  If not, then fail out
            If($crmUrl -match 'http.*://.*')
            {
                # Instance URL is the full URL, continue on
            }
            Else
            {
                Write-Warning "Enter the full instance URL.  Expected format is https://INSTANCE.domain.com"
                Break
            }
        }
    }

    # User to connect to Dynamics 365
    # If you want to bypass the login screen, hard code your credentials below
    # $user = "USER@DOMAIN.onmicrosoft.com"
    # User's password
    # $pwd = "PASSWORD"
    # If you hard code credentials, you need to convert password to secure string
    # $securePwd = ConvertTo-SecureString -String $pwd -AsPlainText -Force
    # If you hard code credentials, need to convert it into a credential object
    # $creds = New-Object System.Management.Automation.PSCredential ($user, $securePwd)

    # Prompt for user credentials
    Try{
        $creds = Get-Credential ""
    }
    Catch
    {
        $ErrorMsg = $_.Exception.Message
        Write-Warning "Failed to validate credentials: $ErrorMsg "
        Break
    }
}
#/****************Retrieve Solution Variables****************

#****************PowerApps Checker Ruleset****************

# Define the Geography for the rules. More information here: 
    # https://docs.microsoft.com/en-us/powershell/module/microsoft.powerapps.checker.powershell/get-powerappscheckerrules?view=pa-ps-latest#parameters

    # Accepted values:	PreviewUnitedStates, UnitedStates, Europe, Asia, Australia, Japan, India, Canada, SouthAmerica, UnitedKingdom

Clear-Host

# Create an array for the geo options for PowerApps Checker
$scGeoOptions = @{1 ="PreviewUnitedStates"; 2 = "UnitedStates"; 3 = "Europe"; 4 = "Asia"; 5 = "Australia"; 6 = "Japan"; 7 = "India"; 8 = "Canada"; 9 = "SouthAmerica"; 10 = "UnitedKingdom"}
Write-Host "Choose the PowerApps Checker Geo."

# Output the array into a table format
$scGeoOptions | Sort-Object Name | Format-Table

# Prompt user for geo option
$scGeoInt = Read-Host "Enter the number of the appropriate Geo (1-10)"

# Check to if it's numeric and 1 - 10
If($scGeoInt -match '[A-z]')
{
    Write-Warning "Only enter the numeric value for the Geo"
    Break
}
Elseif (-not ($scGeoInt -match '\b([1-9]|[1][0])\b'))
{
    Write-Warning "Only values 1-10 are expected"
    Break
}
Else
{
    switch ($scGeoInt)
    {
        1  {$scGeo = 'PreviewUnitedStates' }
        2  {$scGeo = 'UnitedStates' }
        3  {$scGeo = 'Europe' }
        4  {$scGeo = 'Asia' }
        5  {$scGeo = 'Australia' }
        6  {$scGeo = 'Japan' }
        7  {$scGeo = 'India' }
        8  {$scGeo = 'Canada' }
        9  {$scGeo = 'SouthAmerica' }
        10 {$scGeo = 'UnitedKingdom' }
    }
}
#/****************PowerApps Checker Ruleset****************

#****************Azure Application ID Variables****************
Clear-Host
Write-Host "Enter in your Azure Application Information"
# TenantId of your Azure subscription
$tenantId = Read-Host "TenantId"

#Validate the TenantId is a valid GUID
If($tenantId -notmatch '\b([0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z])\b')
{
    Write-Warning "Not a valid TenantId"
    Break
}

# Client ApplicationId from Azure subscription that was configured for PowerApps Checker.  
$clientApplicationId = Read-Host "ClientApplicationId"

#Validate the ClientApplicationId is a valid GUID
If($clientApplicationId -notmatch '\b([0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z]-[0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z][0-9A-z])\b')
{
    Write-Warning "Not a valid ClientApplicationId"
    Break
}

# Client Application Secret so you don't have to enter in credentials
$secureAppSecret = Read-Host -AsSecureString "ClientApplicationSecret"
# If you hard code the appSecret, then you need to secure the Client Application Secret
# $secureAppSecret = ConvertTo-SecureString -String $appSecret -AsPlainText -Force

#/****************Azure Application ID Variables****************

#******************************************************************************************************************
#                              Retrieve and Analysis of Solutions
#******************************************************************************************************************

#***************************Retrieve All Unmanaged Solutions*******************************************************
# Check to see if the user opted to use existing files
If($existingFiles -eq "y")
{
    # User opted to analyze existing files. Skipping retrieving of solutions from CDS/D365 
}
Else
{
    Clear-Host
    Write-Host ("{0}{1}{2}" -f "Connecting to ", $crmUrl, " to retrieve solution files")

    # Connect to Dynamics 365 service. If deploymentInt is 1, connect online.  Otherwise, connect onprem
    If($deploymentInt -eq 1)
    {
        $crmSvc = Connect-CrmOnline -Credential $creds -ServerUrl $crmUrl
    }
    Else
    {
        $crmSvc =  Connect-CrmOnPremDiscovery -Credential $creds -ServerUrl $crmUrl 
    }

    # Extend the timeout to allow more time if larger solutions are being extracted
    Set-CrmConnectionTimeout -conn $crmSvc -TimeoutInSeconds 300  

    # Create fetch query that retrieves all unmanaged solutions and are not of Default Solution
    # Default solution is not supported for export, see: https://docs.microsoft.com/powerapps/maker/common-data-service/import-update-export-solutions#export-solutions
$fetch = @"
<fetch>
    <entity name="solution">
    <attribute name = "friendlyname"/>
    <attribute name = "uniquename"/>
    <attribute name = "createdby"/>
    <attribute name = "version"/>
    <filter>
        <condition attribute="ismanaged" operator="eq" value="0"/>
        <condition attribute="isvisible" operator="eq" value="1"/>
        <condition attribute="solutiontype" operator="eq" value="0"/>
    </filter>
    </entity>
</fetch>
"@

    # Execute Fetch query that retrieves all unmanaged solutions
    $solutions = Get-CrmRecordsByFetch -conn $crmSvc -Fetch $fetch

    Write-Host ("{0}{1}{2}" -f "Retrieved ", $solutions.Count, " solution files")

    # Create a directory to output the solution to
    If(Test-Path $solutionsDirectory)
    {
        # Do nothing since it already exists
    }
    Else
    {
        New-Item -ItemType Directory -Force -Path $solutionsDirectory
    }

    # Export all unmanaged solutions to the $solutionsDirectory
    foreach($solution in $solutions.CrmRecords)
    {
        $sName = $solution.friendlyname
        $sVersion = ($solution.version).Replace(".", "_")
        Write-Host "Attempting to export "$sName
        try
        {
            $s = Export-CrmSolution -conn $crmSvc -SolutionName $solution.friendlyname -SolutionFilePath $solutionsDirectory -SolutionZipFileName $sName"_"$sVersion".zip"
        }
        catch
        {
            throw $_
        }
    }
}

#******************************************************************************************************************
#                              Analyze Solution Files with PowerApps Checker
#******************************************************************************************************************

# Initializing the ruleset for PowerApps Checker
$ruleSets = Get-PowerAppsCheckerRulesets -Geography $scGeo
$rules = $ruleSets | where Name -EQ 'Solution Checker'

# Build an array of all of the solution files
$files = Get-ChildItem -Path $solutionsDirectory -File -Filter *.zip

# For each of the solution files we want to do the following
#   * Create a directory for each solution 
#   * Run the PowerApps Checker analysis for the solution
#   * Extract the sarif file into an analysis directory

# Iterate each file in the array to process within PowerApps Checker
foreach($file in $files)
{
    try
    {   
        # If the file has spaces, need to replace those with underscores (_)
        If($file.Name -match " ")
        {
            $fileName = ($file.Name).Replace(" ","_")
            Rename-Item -Path $file.FullName -NewName $fileName

            $fileName = $file.DirectoryName + "\" + $fileName
            $file = Get-Item -Path $fileName
        }

        # Build directory variables and define CSV file
        $eachSolutionsDirectory = ("{0}{1}{2}" -f $solutionsDirectory, '\', $file.BaseName)
        $resultsFile = ("{0}{1}{2}{3}" -f $eachSolutionsDirectory, "\" , $file.BaseName, "_Results.csv")

        # Create a directory to output the PowerApps Checker results to
        If(Test-Path $eachSolutionsDirectory)
        {
            #Remove all previous SARIF files
            Get-ChildItem –path $eachSolutionsDirectory –recurse | Remove-Item -Recurse -Force
        }
        Else
        {
            $f = New-Item -ItemType Directory -Force -Path $eachSolutionsDirectory
        }

        # Check to see if the solution file size is 30MB or larger. If solution size is larger than 30 MB, it must be submitted to PowerApps Checker via SAS URI
        $fileSize = $file.Length/1MB

        # If so, prompt that it must be uploaded to a blob storage and ask to continue to try and upload it
        If($fileSize -gt 30)
        {
            # Prompting the user that the file is 30 MB and check if they want to continue to use Blob storage
            Write-Host "This file size is larger than 30 MB and must be submitted to PowerApps Checker via SAS URI."
            $useSASURI = Read-Host "Do you want to upload this file to Azure blob? (y/n)"
            
            # Only keep the first character and put it to lower
            $useSASURI = ($useSASURI.Substring(0,1)).ToLower()
            
            # If yes, then upload the file to Azure blob.  
            If($useSASURI -eq "y")
            {
                # Predefined Azure Resource Names
                $storageAccount = "pacsolutions"
                $resourceGroup = "PowerAppsChecker"
                $containerName = "paccontainer"
                $blobName = $file.Name

                If(!$creds)
                {
                    # Prompt for user credentials
                    Try{
                        $creds = Get-Credential ""
                    }
                    Catch
                    {
                        $ErrorMsg = $_.Exception.Message
                        Write-Warning "Failed to validate credentials: $ErrorMsg "
                        Break
                    }
                }

                # Sign into Azure subscription
                $sub = Connect-AzAccount -Credential $creds

                # Set the Azure location
                $azLocation = Get-AzLocation | select Location  | Sort-Object Location
                for($i=0;$i-le $azLocation.length-1;$i++)
                {
                    "{0}      {1}" -f ($i+1), $azLocation[$i].Location
                }

                $rLocation = Read-Host ("Enter the number for the appropriate Azure StorageAccount location (1-{0})" -f ($azLocation.Count))

                # Check to if it's numeric 
                If($rLocation -match '[A-z]')
                {
                    Write-Warning "Only enter the numeric value for the Location"
                    Break
                }
                # Check to if it's 1 - 40
                Elseif (-not ($rLocation -match '\b([1-9]|[1-3][0-9]|[4][0])\b'))
                {
                    Write-Warning "Only values 1-40 are expected"
                    Break
                }
                # Passing validation, we'll set the location value
                Else
                {
                    $location = $azLocation[($rLocation-1)].Location
                }

                # You must retrieve all StorageAccounts as the Get-AzStorageAccount command requires ResourceGroup. The StorageAccount may not be within the defined ResourceGroup    
                $azAllStorageAccount = Get-AzStorageAccount -ErrorAction SilentlyContinue

                # Iterate through each StorageAccount to determine if the account exists already
                foreach($azStorageAccount in $azAllStorageAccount)
                {
                    # Check to see if the StorageAccount already exists
                    If($azStorageAccount.StorageAccountName = $storageAccount) {break}
                    {
                        # StorageAccount exists, break out of the loop and use that storage Account
                    }
                    Else
                    {
                        # Check to see if the Resource Group exists before creating it
                        If($azResourceGroup = Get-AzResourceGroup -Name $resourceGroup -ErrorAction SilentlyContinue)
                        {
                            # ResourceGroup exists so use existing ResourceGroup
                        }
                        Else
                        {
                            $azResourceGroup = New-AzResourceGroup -Name $resourceGroup -Location $location
                        }

                        # Create the storage account
                        $azStorageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroup `
                            -Name $storageAccount `
                            -SkuName Standard_LRS `
                            -Location $location `
                            -Kind StorageV2 `
                            -AccessTier Hot `
                    }
                }
 
                # Set the context for the StorageAccount
                $ctx = $azStorageAccount.Context

                # Check to see if the Container exists before creating it
                If($azContainerName = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue)
                {
                    # Container exists so use existing Container
                }
                Else
                {
                    # Create a container
                    $azContainerName = New-AzStorageContainer -Name $containerName -Context $ctx -Permission blob
                }
                
                Clear-Host
                Write-Host "Uploading solution to blob storage"

                # Upload the solution file to the blob storage
                Set-AzStorageBlobContent `
                    -File $file.FullName `
                    -Container $containerName `
                    -Blob $blobName `
                    -Context $ctx | Out-Null

                # Create a SAS token with read/write blob permission
                $sasURI = New-AzStorageBlobSASToken -Container $containerName -Context $ctx -Blob $blobName -Permission rw -FullUri
                Write-Host "Solution uploaded successfully and token created: " + $sasURI
                Write-Host ""
                Write-Host ("{0}{1}{2}" -f "Submitting ", $file.BaseName, " solution to PowerApps Checker for analysis")

                # Send the solution to PowerApps Checker for analysis  
                $checkerResults = Invoke-PowerAppsChecker -FileUnderAnalysisSasUri $sasURI -Ruleset $rules -OutputDirectory $eachSolutionsDirectory -ClientApplicationId $clientApplicationId -TenantId $tenantId -ClientApplicationSecret $secureAppSecret

                Write-Host ("{0}{1}" -f "Analysis completed for ", $file.BaseName)
            }
            # Otherwise, prompt to use an existing SAS URI
            ElseIf($useSASURI -eq "n")
            {
                $useExistSAS = Read-Host "Do you have an existing SAS URI you want to use? (y/n)"
                If($useExistSAS -eq "y")
                {
                    $sasURI = Read-Host "Enter in full SAS URI"

                    Write-Host ("{0}{1}{2}" -f "Submitting ", $file.BaseName, " solution to PowerApps Checker for analysis")

                    # Send the solution to PowerApps Checker for analysis  
                    $checkerResults = Invoke-PowerAppsChecker -FileUnderAnalysisSasUri $sasURI -Ruleset $rules -OutputDirectory $eachSolutionsDirectory -ClientApplicationId $clientApplicationId -TenantId $tenantId -ClientApplicationSecret $secureAppSecret

                    Write-Host ("{0}{1}" -f "Analysis completed for ", $file.BaseName)
                }
                ElseIf($useExistSAS -eq "n")
                {
                    Write-Host "Since file size is > 30MB, skipping processing of this file"
                    Break
                }
                Else
                {
                    Write-Host "You must only enter 'y' or 'n'"
                    Break
                }
            }
            Else
            {
                Write-Host "You must only enter 'y' or 'n'"
                Break
            }
        }
        # File is under 30MB and can submit it from the local location
        Else
        {
            Write-Host ("{0}{1}{2}" -f "Submitting ", $file.BaseName, " solution to PowerApps Checker for analysis")

            # Send the solution to PowerApps Checker for analysis  
            $checkerResults = Invoke-PowerAppsChecker -FileUnderAnalysis $file.FullName -Ruleset $rules -OutputDirectory $eachSolutionsDirectory -ClientApplicationId $clientApplicationId -TenantId $tenantId -ClientApplicationSecret $secureAppSecret

            Write-Host ("{0}{1}" -f "Analysis completed for ", $file.BaseName)
        }

        # Build an array for each sarif file
        $sarif = Get-ChildItem -Path $eachSolutionsDirectory -File -Filter *.zip

        # Extract all of the sarif files into the analysisDirectory
        foreach($file in $sarif)
        {
            try
            {    
                Expand-Archive -LiteralPath $file.FullName -DestinationPath $eachSolutionsDirectory

                Write-Host ("{0}{1}" -f "Extracting analysis results to ", $eachSolutionsDirectory)

            }
            catch
            {
                throw $_
            }
        }

        #*******************************************************************************************************
        #                       Format the sarif results into CSV format
        #*******************************************************************************************************

        # Object used to write out each row to the results file
        $outputRow = New-Object PSObject

        # Define the headers
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "RuleId" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "Severity" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "RuleText" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "FileName" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "Line" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "Snippet" -Value ""
        Add-Member -InputObject $outputRow -MemberType NoteProperty -Name "Guidance" -Value ""
        
        # Initialize the output file
        $outputRow |Export-Csv $resultsFile -NoTypeInformation

        # Retrieve all SARIF files
        $analysisFiles = Get-ChildItem -Path $eachSolutionsDirectory -File -Filter *.sarif

        Write-Host ("{0}" -f "Formatting each analysis file into CSV format.")

        # Iterate through all of the .sarif files
        foreach($file in $analysisFiles)
        {
            $messages = Get-Content $file.FullName -Filter *.sarif | ConvertFrom-Json 
            $guidance = $messages.runs.tool.driver.rules
            
            for($i=0; $i -lt $messages.runs.results.Count; $i++)
            {
                $runResults = $messages.runs.results[$i]
                $guidanceUrl = $guidance | Where-Object {$_.id -EQ $runResults.ruleId}

                $rowValues = @{
                    "RuleId" = $runResults.ruleId
                    "Severity"= $runResults.properties.severity
                    "RuleText" = $runResults.message.text
                    "FileName" = $runResults.locations.physicalLocation.artifactLocation.uri
                    "Line" = $runResults.locations.physicalLocation.region.startLine
                    "Snippet" = $runResults.locations.physicalLocation.region.snippet.text
                    "Guidance" = $guidanceUrl.helpUri
                }

                $newRow = New-Object PSObject -Property $rowValues
                Export-Csv $resultsFile -InputObject $newRow  -Append -Force
            }
        }
            Write-Host ("{0}{1}" -f "Formatting complete. Results may be viewed within: ", $eachSolutionsDirectory)
    }

    catch
    {
        throw $_
    }
}