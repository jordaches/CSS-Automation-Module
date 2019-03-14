function SplitText
{
    param
    (
        [string]
        $String
    )
    #This is to seperate title cased strings to a sentence. eg. SplitText('WhatTheF***')
    [Regex]::Split($String,("(?<!^)(?=[A-Z])"))
}

function Get-RandomPassword
{
    param
    ([int]$Length=10)
    $letters = 'abcdefghijklmnopqrstuvwxyz'
    $cletters = $letters.ToUpper().ToCharArray()
    $numbers = 1,2,3,4,5,6,7,8,9,0
    $specialchars = '!@#$%&*()+'.ToCharArray()
    $string = ''
    $string += $specialchars | Get-Random -Count 2
    $string += $numbers | Get-Random -Count 2
    $string += $cletters | Get-Random -Count 2
    $string += $letters.ToCharArray() | Get-Random -Count ($Length - 6)
    $pass = ($string.ToCharArray() | Get-Random -Count $string.Length) -join ''
    return $pass.Replace(' ','')
}

function New-TempHpsaOpenPortScript
{
    do
    {
        $randomval = "$env:windir\temp\$((Get-Random).ToString()).ps1"
    }
    until (!(Test-Path $randomval))
    $script = 
@'
Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Where {($_.Direction -eq 'Inbound') -and ($_.DisplayName -match 'SMB-In')} | Enable-NetFirewallRule 
'@
    $script | Out-File -FilePath $randomval -Force
    return $randomval
}

function Add-AzureRmVmAntimalware
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.t-systems.co.za/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param(
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [pscredential]
        $Credential, 
        #Azure SubscriptionId
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,
        #Azure VM Name 
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=2,
            ParameterSetName='Parameter Set 1')]
        [string]
        $VmName,
        #Azure Resource Group
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=3,
            ParameterSetName='Parameter Set 1')]
        [string]
        $ResourceGroupName
    )

    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            $FunctionLogin = $true
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
    try
    {
        Write-Verbose "Looking for VM $VMName in $ResourceGroupName.."
        $Location = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
        Write-Verbose "Found VM $VMName in $ResourceGroupName..."
        $AV = Get-AzureRmVMExtensionImage `
                                -Location $Location.Location `
                                -PublisherName 'Microsoft.Azure.Security' `
                                -Type IaaSAntimalware `
                                -ErrorAction Stop | 
                                    Sort-Object -Property Version -Descending | 
                                        Select -First 1
        <# Getting major type number in below line as Set-AzureRMVMExtension does not support minor version numbers. #>
        $avversion = $av.Version.Substring(0,$av.Version.Substring(0,($av.Version.LastIndexOfAny('.'))).LastIndexOfAny('.'))
        $job = Set-AzureRmVMExtension `
            -VMName $VMName `
            -ResourceGroupName $ResourceGroupName `
            -ExtensionType $av.Type `
            -Publisher $av.PublisherName `
            -Location $av.Location `
            -Name $AV.Type `
            -Settings @{"AntimalwareEnabled" = "true"} `
            -TypeHandlerVersion $avversion `
            -ErrorAction Stop -AsJob
        Wait-Job -Job $job -Timeout 3600
        Receive-Job -Job $job | Out-Null
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        Write-Verbose "Antimalware on $VmName enabled successfully."
    }
    catch
    {
        if ($FunctionLogin)
        {
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
    }
}

function Add-AzureRMVMUpdateManagementConfig
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.t-systems.co.za/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param(
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [pscredential]
        $Credential, 
        #Azure SubscriptionId
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,
        #Azure VM Name 
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=2,
            ParameterSetName='Parameter Set 1')]
        [string]
        $VmName,
        #Azure Resource Group
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=3,
            ParameterSetName='Parameter Set 1')]
        [string]
        $ResourceGroupName,
        #Azure Workspace name (Needs to be deployed via Update Solution)
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=4,
            ParameterSetName='Parameter Set 1')]
        [string]
        $WorkSpaceName,
        #Azure Automation Account Name (Needs to be deployed via Update Solution)
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=5,
            ParameterSetName='Parameter Set 1')]
        [string]
        $AutomationAccountName
    )
    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            $FunctionLogin = $true
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
    try
    {
        Write-Verbose "Retrieving Update management details."
        $AutomationAcc = Get-AzureRMAutomationAccount -ErrorAction Stop | ? {$_.AutomationAccountName -eq $AutomationAccountName}
        $AutomationResId = Get-AzureRmResource -ResourceType 'Microsoft.Automation/automationAccounts' -Name $AutomationAcc.AutomationAccountName -ErrorAction Stop
        $WorkSpaceInfo = Get-AzureRmOperationalInsightsWorkspace -ErrorAction Stop | ? {$_.Name -eq $WorkSpaceName}
        $VM = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VmName -ErrorAction Stop
    }
    catch
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return
    }
    $Diagnostics = Get-AzureRmDiagnosticSetting -ResourceId $AutomationResId.ResourceId -ErrorAction Stop
    if (-not $Diagnostics.WorkspaceId -eq $WorkSpaceInfo.ResourceId)
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        Write-Error -Message 'Correlation between Automation Account and Workspace not found. Please deploy Update Management solution via Azure portal.'
        return
    }
    else
    {
        Write-Verbose -Message "Correlation between '$AutomationAccountName' and '$WorkSpaceName' found."
    }
    $MMAExentsionName = "MicrosoftMonitoringAgent"
    $MMATemplateLinkUri = "https://wcusonboardingtemplate.blob.core.windows.net/onboardingtemplate/ArmTemplate/createMmaWindowsV3.json"
    $MMADeploymentParams = 
    @{
        "vmName" = $vm.Name.ToString()
        "vmLocation" = $VM.Location.ToString()
        "vmResourceId" = $VM.Id.ToString()
        "vmIdentityRequired" = $false
        "workspaceName" = $WorkSpaceInfo.Name.ToString()
        "workspaceId" = $WorkSpaceInfo.CustomerId.Guid.ToString()
        "workspaceResourceId" = $WorkSpaceInfo.ResourceId.ToString()
        "mmaExtensionName" = $MMAExentsionName
    }
    $DeploymentName = "AutomationControl-PS-" + (Get-Date).ToFileTimeUtc()
    try
    {
        New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri $MMATemplateLinkUri -Name $DeploymentName -TemplateParameterObject $MMADeploymentParams -ApiVersion 2015-06-15 -Force | Out-Null
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        Write-Verbose "Azure Update Management enabled sucessfully on $VmName"
        return
    }
    catch
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return
    }
}

function Enable-AzureRmVmBackup
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.t-systems.co.za/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        $Credential,
    
        #Azure RM Subscription
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,
    
        # Azure RM Resource Group Name
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=2,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ResourceGroup,
    
        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=3,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName,

        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=4,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultID,

        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=5,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $PolicyName
    )
    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            $FunctionLogin = $true
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
    try
    {
        Write-Verbose "Retrieving backup policy."
        $Policy = Get-AzureRmRecoveryServicesBackupProtectionPolicy -Name $PolicyName -VaultId $VaultID -ErrorAction Stop
        Write-Verbose "Attempting to enable backup on $VMName"
        Enable-AzureRmRecoveryServicesBackupProtection -Name $VMName -Policy $Policy -ResourceGroupName $ResourceGroup -VaultId $VaultID -ErrorAction Stop
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        Write-Verbose "Backups on `"$VMName`" enabled sucessfully. Policy: $PolicyName"
    }
    catch
    {
        Write-Verbose "Failed to enable backup on $VMName"
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return
    }
}

function Disable-AzureRmVmBackup
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.t-systems.co.za/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [pscredential]
        $Credential,

        #Azure SubscriptionId
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,
    
        # Azure RM Resource Group Name
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=2,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ResourceGroup,
    
        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=3,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName,

        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=4,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultID,
        # Vm Hostname
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=5,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemoveRecoveryPoints = 'false'
    )
    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            $FunctionLogin = $true
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
    try
    {
        $container = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM -FriendlyName $VMName -VaultId $VaultID -ErrorAction Stop
        $item = Get-AzureRmRecoveryServicesBackupItem -Container $container -Name $VMName -VaultId $VaultID -WorkloadType AzureVM -ErrorAction Stop
        if ($RemoveRecoveryPoints = 'true')
        {
            Disable-AzureRmRecoveryServicesBackupProtection -Item $item -RemoveRecoveryPoints -Force -VaultId $VaultID -ErrorAction Stop | Out-Null
            Write-verbose "Backups for `"$VMName`" disabled sucessfully. Recovery Points removed."
        }
        else
        {
            Disable-AzureRmRecoveryServicesBackupProtection -Item $item -Force -VaultId $VaultID -ErrorAction Stop | Out-Null
            Write-verbose "Backups for `"$VMName`" disabled sucessfully."
        }
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
    }
    catch
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return
    }
}

function Get-AzureAvailableResources
{
    param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,`
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default Parameter Set')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("Creds")]
        [pscredential]
        $Credential
        )
    #Script begins here...

    #Logging in
    Login-AzureRmAccount -Credential $Credential -ErrorAction Stop -Scope Process -Verbose | Out-Null

    #Select Subscription
    $Subscription = Get-AzureRmSubscription -ErrorAction Stop -Verbose
    Select-AzureRmSubscription -SubscriptionObject $Subscription[0] -Scope Process -Verbose | Out-Null
    #Build Locations/VmSizes/VMSizes Properties JSON file
    $AzureRMLocations = Get-AzureRmLocation -ErrorAction SilentlyContinue -Verbose
    $VMSizes = Get-AzureRmComputeResourceSku -ErrorAction SilentlyContinue -Verbose | Where {$_.ResourceType -eq 'virtualMachines'}
    $PublisherName = 'MicrosoftWindowsServer'
    $ImageOffer = 'WindowsServer'

    ########<<<<<<<<<<<<<<< Creating inventory of VMs Sizes/Properties and Locations >>>>>>>>>>>>>>>###############
    $CustomObject = @()
    Foreach($A in $AzureRMLocations)
    {
            $RegionSupportsHA = 'false'
            #Checking if images exist in region before creating object.
            $images = $null
            $images = Get-AzureRmVMImageSku -Location $A.location -PublisherName $PublisherName -Offer $ImageOffer -ErrorAction SilentlyContinue -Verbose | 
                                        Select -ExpandProperty Skus | 
                                        Where {($_ -notmatch '2008')}
            if($images -ne $null)
            {
                $CustomObject += 
                    [ordered]@{
                                #Location
                                name =  $A.DisplayName
                                id =  $A.Location
                                vmsizes = Foreach ($vmsize in ($VMSizes | Where {$_.Locations -eq $A.location}))
                                            {
                                                if(($vmsize.LocationInfo.Zones.Count) -ge 2){$RegionSupportsHA = 'true'}
                                                [ordered]@{
                                                            #VMSize Properties
                                                            name = $vmsize.Name
                                                            id = $vmsize.Name
                                                            vCPU = ($vmsize.Capabilities | Where {$_.name -eq 'vCPUs'}).Value
                                                            MemoryGB = ($vmsize.Capabilities | Where {$_.name -eq 'MemoryGB'}).Value
                                                            OSVhdSizeMB = ($vmsize.Capabilities | Where {$_.name -eq 'OSVhdSizeMB'}).Value
                                                            TempStorageMB = ($vmsize.Capabilities | Where {$_.name -eq 'MaxResourceVolumeMB'}).Value
                                                            MaxDataDiskCount = ($vmsize.Capabilities | Where {$_.name -eq 'MaxDataDiskCount'}).Value
                                                            PremiumStorageSupport = ($vmsize.Capabilities | Where {$_.name -eq 'PremiumIO'}).Value
                                                            LowPriorityCapable = ($vmsize.Capabilities | Where {$_.name -eq 'LowPriorityCapable'}).Value
                                                            HighAvailability = if(($vmsize.LocationInfo.Zones.Count) -ge 2){$vmsize.LocationInfo.Zones}else{"Not available"}
                                                            Tier = $vmsize.Tier
                                                        }                                       
                             
                                            }
                                #Images based on locations.
                                "Images" = $images | % {[ordered]@{
                                                        name = "$(SplitText -String $PublisherName) $($_.Replace('-',' '))"
                                                        id = $_
                                                    }}
                                #HA Supported Region
                                "HASupportedRegion" = $RegionSupportsHA
                                "LogAnalyticsSupportedRegion" = if($A.Providers -contains 'Microsoft.LogAnalytics'){'true'}else{'false'}
                                "AzureRegionServices" = $A.Providers
                                "DiskTypes" = [ordered]@{
                                                            Managed = (
                                                                        [ordered]@{
                                                                            name = 'Premium SSD'    
                                                                            id = 'Premium_LRS'
                                                                        },
                                                                        [ordered]@{
                                                                            name = 'Standard SSD'    
                                                                            id = 'StandardSSD_LRS'
                                                                        },
                                                                        [ordered]@{
                                                                            name = 'Standard HDD'    
                                                                            id = 'Standard_LRS'
                                                                        }
                                                                      )
                                                            Unmanaged = (
                                                                          [ordered]@{
                                                                            name = 'Premium SSD'    
                                                                            id = 'Premium_LRS'
                                                                        },
                                                                          [ordered]@{
                                                                            name = 'Standard HDD'    
                                                                            id = 'Standard_LRS'
                                                                          }
                                                                          )
                                                        }                                                        
                        }
            }
    }
    Logout-AzureRmAccount -Verbose -Scope Process | Out-Null
    $json = @{"Locations" = $CustomObject} | ConvertTo-Json -Depth 100 -Verbose
    return $json
}

function Get-AzureClientResources
{
    param(
    [Parameter(Mandatory=$true, 
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true, 
                ValueFromRemainingArguments=$false, 
                Position=0,
                ParameterSetName='Default Parameter Set')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [Alias("Creds")]
    [pscredential]
    $Credential
    )

    #Logging in
    Login-AzureRmAccount -Credential $Credential -ErrorAction Stop -Force -verbose -Scope Process | Out-Null
    #Get Tenants
    $Tenant = Get-AzureRmTenant -verbose
    #Tennant Array
    $TennantArray = @()
    Foreach($t in $Tenant)
    {
    #Tenant details
    Connect-AzureAD -Credential $Credential -TenantId $t.Id -verbose | Out-Null
    $TenantDetails = Get-AzureADTenantDetail
    Disconnect-AzureAD -Confirm:$false -verbose | Out-Null
    #Get Subscriptions
    $Subscription = Get-AzureRmSubscription -ErrorAction Stop -verbose #| Select -Last 1
    #SubscriptionArray
    $SubscriptionArray = @()
    Foreach($s in $Subscription)
    {
        #Select Subscription
        Select-AzureRmSubscription -SubscriptionObject $S -verbose -Scope Process | Out-Null

        #Get Locations
        $Locations = Get-AzureRmLocation -verbose
        #Location Array
        $LocationArray = @()
        Foreach($l in $Locations)
        {
            #Resource Groups
            $ResourceGroups = $null
            $ResourceGroups = Get-AzureRmResourceGroup -Location $l.Location -verbose
            if($ResourceGroups -ne $null)
            {
                #ResourceGroup Array
                $RGArray = @()
                foreach($ResourceGroup in $ResourceGroups)
                {
                #Networks and Subnets
                $VMNets = @()
                $VMNets += Get-AzureRmVirtualNetwork `
                                    -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | 
                                    %{
                                        #Subnet Array
                                        $subnets = @()
                                        $subnets += $subnets += $($_.Subnets | %{[ordered]@{name = "$($_.Name)";prefix = $_.AddressPrefix;id=$_.Id}})
                                        [ordered]@{
                                            name = $_.Name
                                            id = $_.Name
                                            Location = $_.Location
                                            AddressSpace = $_.AddressSpace.AddressPrefixes
                                            Subnets = $subnets
                                            Tags = foreach($ta in $vmnet.Tag.Keys){[ordered]@{name="$ta";value=($vmnet.Tag["$ta"])}}
                                        }
                                    }
                #Storage Accounts
                $StorageAccounts = @()
                $StorageAccounts += Get-AzureRmStorageAccount `
                                            -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | 
                                            %{
                                                [ordered]@{
                                                    name = $_.StorageAccountName
                                                    id = $_.StorageAccountName
                                                    SKUName = $_.Sku.Name.ToString()
                                                    SKUTier = $_.Sku.Tier.ToString()
                                                    Kind = $_.Kind.ToString()
                                                    Location = $_.PrimaryLocation
                                                    BlobEndpoint = $_.PrimaryEndpoints.Blob
                                                    TableEndpoint = $_.PrimaryEndpoints.Table
                                                    FileEndpoint = $_.PrimaryEndpoints.File
                                                    QueueEndpoint = $_.PrimaryEndpoints.Queue
                                                    Tags = foreach ($ta in $_.Tags.Keys){[ordered]@{name=$ta;Value=$_.Tags[$ta]}}
                                                }                      
                                            }
                #Availability Sets
                $AvailabilitySets = @()
                $AvailabilitySets += Get-AzureRmAvailabilitySet `
                                                        -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | 
                                                        %{
                                                            [ordered]@{
                                                                name = $_.Name
                                                                id = $_.Id
                                                                Managed = $_.Managed
                                                                Sku = $_.Sku
                                                                FaultDomain = $_.PlatformFaultDomainCount
                                                                UpdateDomain = $_.PlatformUpdateDomainCount
                                                                Location = $_.Location
                                                                Tags = foreach ($ta in $_.Tags.Keys){[ordered]@{name=$ta;Value=$_.Tags[$ta]}}
                                                            }
                                                        }
                #Automation Accounts
                $AutomationAccounts = @()
                $AutomationAccounts += Get-AzureRmAutomationAccount `
                                                        -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | 
                                                        %{
                                                            [ordered]@{
                                                                name = $_.AutomationAccountName
                                                                id = $_.AutomationAccountName
                                                                Location = $_.Location
                                                                Tags = foreach ($ta in $_.Tags.Keys){[ordered]@{name=$ta;Value=$_.Tags[$ta]}}
                                                            }
                                                        }

                #Log Analytics Workspace
                $LogAnalyticsWorkspace = @()
                $LogAnalyticsWorkspace += Get-AzureRmOperationalInsightsWorkspace `
                                                        -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose |
                                                        %{
                                                             [ordered]@{
                                                                name = $_.Name
                                                                id = $_.ResourceId
                                                                Location = $_.Location
                                                                Tags = foreach ($ta in $_.Tags.Keys){[ordered]@{name=$ta;Value=$_.Tags[$ta]}}
                                                                Sku = $_.Sku
                                                                CustomerID = $_.CustomerId
                                                                PortalUrl = $_.PortalUrl
                                                            }
                                                        }
                
                #Virtual Machines
                $VMs = @()
                $VMs += Get-AzureRmVM `
                            -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose |
                            %{
                                [ordered]@{
                                    name = $_.Name
                                    id = $_.Id
                                    Location = $_.Location
                                    ResourceGroupName = $_.ResourceGroupName
                                    VMSize = $_.HardwareProfile.VmSize
                                    LicenseType = $_.LicenseType
                                    HostName = $_.OSProfile.ComputerName
                                    AdminUserName = $_.OSProfile.AdminUsername
                                    OSType = $_.StorageProfile.OsDisk.OsType.ToString()
                                    ImageSKU = $_.StorageProfile.ImageReference.Sku
                                    OSDiskName = $_.StorageProfile.OsDisk.Name
                                    OSDiskSize = $_.StorageProfile.OsDisk.DiskSizeGB
                                    ManagedDisk = $_.StorageProfile.OsDisk.ManagedDisk.Id
                                    Tags = foreach ($ta in $_.Tags.Keys){[ordered]@{name=$ta;Value=$_.Tags[$ta]}}
                                }
                            }

                #Recovery Services Vault
                $RecoveryServicesVault = @()
                $RecoveryServicesVault += Get-AzureRmRecoveryServicesVault `
                                                                -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose |
                                                                %{
                                                                    [ordered]@{
                                                                        name = $_.Name
                                                                        id = $_.ID
                                                                        Location = $_.Location
                                                                        ResourceGroupName = $_.ResourceGroupName
                                                                        BackupPolicyDetails = Get-AzureRmRecoveryServicesBackupProtectionPolicy -VaultId $_.Id | 
                                                                            %{
                                                                                [ordered]@{
                                                                                    name = $_.Name
                                                                                    id = $_.Name
                                                                                    ScheduleRunDays = $_.SchedulePolicy.ScheduleRunDays | %{$_}
                                                                                    ScheduleRunTimes = $_.SchedulePolicy.ScheduleRunTimes | %{if($_){"$($_.ToString()) UTC"}}
                                                                                    ScheduleRunFrequency = $_.SchedulePolicy.ScheduleRunFrequency
                                                                                    IsDailyScheduleEnabled = $_.RetentionPolicy.IsDailyScheduleEnabled
                                                                                    IsWeeklyScheduleEnabled = $_.RetentionPolicy.IsWeeklyScheduleEnabled
                                                                                    IsMonthlyScheduleEnabled = $_.RetentionPolicy.IsMonthlyScheduleEnabled
                                                                                    IsYearlyScheduleEnabled = $_.RetentionPolicy.IsYearlyScheduleEnabled
                                                                                    DailyScheduleDurationCountInDays = $_.RetentionPolicy.DailySchedule.DurationCountInDays
                                                                                    DailyScheduleRetentionTimes = $_.RetentionPolicy.DailySchedule.RetentionTimes | %{if($_){"$($_.ToString()) UTC"}}
                                                                                    WeeklyScheduleDurationCountInDays = $_.RetentionPolicy.WeeklySchedule.DurationCountInDays
                                                                                    WeeklyScheduleRetentionTimes = $_.RetentionPolicy.WeeklySchedule.RetentionTimes  | %{if($_){"$($_.ToString()) UTC"}}
                                                                                    MonthlyScheduleDurationCountInDays = $_.RetentionPolicy.MonthlySchedule.DurationCountInDays
                                                                                    MonthlyScheduleRetentionTimess = $_.RetentionPolicy.MonthlySchedule.RetentionTimess  | %{if($_){"$($_.ToString()) UTC"}}
                                                                                    YearlyScheduleDurationCountInDays = $_.RetentionPolicy.YearlySchedule.DurationCountInDays
                                                                                    YearlyScheduleRetentionTimes = $_.RetentionPolicy.YearlySchedule.RetentionTimes  | %{if($_){"$($_.ToString()) UTC"}}
                                                                                    WorkloadType = $_.WorkloadType
                                                                                }
                                                                            }
                                                                    }
                                                                }
                #Disks
                $Disks = @()
                $Disks += Get-AzureRmDisk `
                                -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | Where {$_.ManagedBy -eq $null} |
                                %{
                                    [ordered]@{
                                        name = $_.Name
                                        id = $_.Id
                                        Location = $_.Location
                                        ResourcegroupName = $_.ResourceGroupName
                                        DiskSizeGB = $_.DiskSizeGB
                                        Tier = $_.Sku.Tier.ToString()
                                        SkuName = $_.Sku.Name.ToString()
                                    }
                                }
                #Network Interfaces
                $NetworkInterfaces = @()
                $NetworkInterfaces += Get-AzureRmNetworkInterface `
                                                        -ResourceGroupName $ResourceGroup.ResourceGroupName | Where {$_.VirtualMachine -eq $null}|
                                                        %{
                                                            [ordered]@{
                                                                name = $_.Name
                                                                id = $_.Name
                                                                Location = $_.Location
                                                                ResourceGroupName = $_.ResourceGroupName

                                                            }
                                                        }
                #Public IPs
                $PublicIPs = @()
                $PublicIPs += Get-AzureRmPublicIpAddress `
                                                -ResourceGroupName $ResourceGroup.ResourceGroupName | Where {$_.IpConfiguration -eq $null} |
                                                %{
                                                    [ordered]@{
                                                        name = $_.Name
                                                        id = $_.name
                                                        Location = $_.Location
                                                        ResourceGroupName = $_.ResourceGroupName
                                                        PublicIpAllocationMethod = $_.PublicIpAllocationMethod
                                                        PublicIpAddressVersion = $_.PublicIpAddressVersion
                                                        IpAddress = $_.IpAddress
                                                    }
                                                }
                #Network Security Groups
                $NSGS = @()
                $NSGS += Get-AzureRmNetworkSecurityGroup `
                                                -ResourceGroupName $ResourceGroup.ResourceGroupName |
                                                %{
                                                    [ordered]@{
                                                        name = $_.Name
                                                        id = $_.Id
                                                        Location = $_.Location
                                                        ResourceGroupName = $_.ResourceGroupName
                                                        NetworkInterface = $_.NetworkInterfaces
                                                        Subnets = $_.Subnets
                                                        #DefaultRules = $_.DefaultSecurityRules
                                                        #SecurityRules = $_.SecurityRules
                                                    }
                                                }
                #ResourceGroup Tags
                $tags = @()
                $tags += foreach ($ta in $ResourceGroups.Tags.Keys)
                        {
                            [ordered]@{
                                        name=$ta
                                        Value=$ResourceGroups.Tags[$ta]
                            }
                        }
                
                #Build RG Object & Append to Array if not null
                $hash = [ordered]@{
                                    name = $ResourceGroup.ResourceGroupName
                                    Location = $ResourceGroup.Location
                                    id = $ResourceGroup.ResourceGroupName
                                    'Storage Accounts' = $StorageAccounts
                                    VMNets = $VMNets
                                    'Availability Sets' = $AvailabilitySets
                                    'Automation Accounts' = $AutomationAccounts
                                    'Virtual Machines' = $VMs
                                    'Recovery Services Vault' = $RecoveryServicesVault
                                    'Unused Disks' = $Disks
                                    'Unused Network Interfaces' = $NetworkInterfaces
                                    'Unused Public IPs' = $PublicIPs
                                    'Network Security Groups' = $NSGS
                                    Tags = $tags                                 
                        }
                if($hash -ne $null){$RGArray += $hash}
                #Cleanup
                Remove-Variable -Name VMNets,StorageAccounts,AvailabilitySets,AutomationAccounts,VMs,RecoveryServicesVault,
                                    Disks,NetworkInterfaces,PublicIPs,NSGS,tags,hash -Force -ErrorAction SilentlyContinue
            }#End Resource Group
                $LocationArray += [ordered]@{
                                    name = $l.DisplayName
                                    id = $l.Location
                                    ResourceGroups = $RGArray
                                }
            }
        }#End Location
        $SubscriptionArray += [ordered]@{
                                name = $s.Name
                                id = $s.SubscriptionId
                                Locations = $LocationArray
                            }
    }#End Subscription
    $TennantArray += [ordered]@{
                        name = $TenantDetails.DisplayName
                        Directory = $t.Directory
                        id = $T.TenantId
                        Subscriptions = $SubscriptionArray
                    }
    }#End Tenant
    Disconnect-AzureRmAccount -verbose -Scope Process | Out-Null
    $Tenants = @{
                    Tenants = $TennantArray
            }
    $data = $Tenants | ConvertTo-Json -Depth 100 -verbose
    Return $data
}

function Delete-AzureRMVMFull
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.t-systems.co.za/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param(
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [pscredential]
        $Credential, 
        #Azure SubscriptionId
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,
        #Azure VM Name 
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=2,
            ParameterSetName='Parameter Set 1')]
        [string]
        $VmName,
        #Azure Resource Group
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=3,
            ParameterSetName='Parameter Set 1')]
        [string]
        $ResourceGroupName
    )
    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    #region Login
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            $FunctionLogin = $true
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
#endregion
    #region Get VM Resources
    try
    {
        $VM = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
        $Nic = Get-AzureRmResource -ResourceId $Vm.NetworkProfile.NetworkInterfaces.Id -ExpandProperties -ErrorAction Stop
    }
    catch
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return
    }
    try
    {
        $PublicIP = Get-AzureRMResource -ResourceId $nic.Properties.ipConfigurations.properties.publicIPAddress.id -ExpandProperties -ErrorAction Stop
    }
    catch
    {
        $PublicIP = $null
    }
#endregion
    #region Create Return Object
    [PSObject]$hash = 
    [ordered]@{
        SubscriptionIdcriptionId = $SubscriptionId
        ResourceGroupName = $ResourceGroupName
        Location = $vm.Location
        VmName = $vm.Name
        NicName = $Nic.Name
        PublicIpName = $PublicIP.Name
        OsDiskName = $VM.StorageProfile.OsDisk.Name
        VmStatus = $vm.StatusCode
        OsDiskStatus = $null
        NicStatus = $null
        DataDisks = @()
        PublicIpStatus = $null
        BackupItemName = $null
        BackupItemStatus = $null
        BootDiagnosticsContainerName = $null
        BootDiagnosticsContainerStatus = $null
    }
#endregion
    #region Stop and Deallocate the VM
    try
    {
        Stop-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VM.Name -Force -ErrorAction Stop | Out-Null
        $hash.VMStatus = 'Stopped and Deallocated'
    }
    catch
    {
        $hash.VMStatus = 'Failed to Stop & Deallocate'
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return ($hash | ConvertTo-Json)
        return
    }
#endregion
    #region Delete the VM
    try
    {
        Remove-AzureRmVM -Name $VM.Name -ResourceGroupName $ResourceGroupName -Force -ErrorAction Stop | Out-Null
        $hash.VMStatus = 'Deleted'  
    }
    catch
    {
        $hash.VMStatus = "Failed to Delete"
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw $Error[0]
        return ($hash | ConvertTo-Json)
        return
    }
#endregion
    #region Remove Storage
    if($vm.StorageProfile.OsDisk.Vhd.Uri -ne $null) #The check for unmanaged disks
    {
        #Unmanaged Disks
        $StorageAccName = $vm.StorageProfile.OsDisk.Vhd.Uri.Replace('https://','').Split('.')[0]
        $OSDiskName = $vm.StorageProfile.OsDisk.Vhd.Uri.Split('/')[-1]
        $StorageAcc = Get-AzureRmStorageAccount -Name $StorageAccName -ResourceGroupName $ResourceGroupName
        $Container = ($vm.StorageProfile.OsDisk.Vhd.Uri.Replace($StorageAcc.PrimaryEndpoints.Blob,'')).Replace($OSDiskName,'').TrimEnd('/')
        try
        {
            Get-AzureStorageBlob -Context $StorageAcc.Context -Blob $OSDiskName -Container $Container | Remove-AzureStorageBlob -Force -ErrorAction Stop | Out-Null
            $hash.OsDiskStatus = 'Deleted'
        }
        catch
        {
            $hash.OsDiskStatus = 'Failed to Delete'
        }
    }
    else
    {
        #Managed Disks
        try
        {
            Remove-AzureRmDisk -ResourceGroupName $ResourceGroupName -DiskName $vm.StorageProfile.OsDisk.Name -Force -ErrorAction Stop | Out-Null
            $hash.OsDiskStatus = 'Deleted'

        }
        catch
        {
            $hash.OsDiskStatus = 'Failed to Delete'
        }
    }
    if($vm.StorageProfile.DataDisks -ne $null)
    {
        foreach($disk in $vm.StorageProfile.DataDisks)
        {    
            if($disk.Vhd.Uri -ne $null)
            {
                #Unmanaged Disks
                $StorageAccName = $disk.Vhd.Uri.Replace('https://','').Split('.')[0]
                $StorageAcc = Get-AzureRmStorageAccount -Name $StorageAccName -ResourceGroupName $ResourceGroupName
                $DiskName = $disk.Vhd.Uri.Split('/')[-1]
                $Container = $disk.Vhd.Uri.Replace($StorageAcc.PrimaryEndpoints.Blob,'').Replace($DiskName,'').TrimEnd('/')
                try
                {
                    Get-AzureStorageBlob -Context $StorageAcc.Context.Context -Blob $DiskName -Container $Container -DefaultProfile $StorageAcc.Context | Remove-AzureStorageBlob -Force -ErrorAction Stop | Out-Null
                    $hash.DataDisks += 
                        @{
                            Name = $disk.Name
                            DiskStatus = 'Deleted'
                        }
                }
                catch
                {
                    $hash.DataDisks += 
                        @{
                            Name = $disk.Name
                            DiskStatus = 'Failed to Delete'
                        }
                }
            }
            else
            {
                #Managed Disks
                try
                {
                    Remove-AzureRmDisk -ResourceGroupName $ResourceGroupName -DiskName $disk.Name -Force -ErrorAction Stop | Out-Null
                    $hash.DataDisks += 
                        @{
                            Name = $disk.Name
                            DiskStatus = 'Deleted'
                        }
                }
                catch
                {
                    $hash.DataDisks += 
                        @{
                            Name = $disk.Name
                            DiskStatus = 'Failed to Delete'
                        }            
                }
            }    
        }
    }
#endregion
    #region Remove NICs
    try
    {
        Remove-AzureRmResource -ResourceId $nic.Id -Force -ErrorAction Stop | Out-Null
        $hash.NicStatus = 'Deleted'
    }
    catch
    {
        $hash.NicStatus = "Failed to Delete"
    }
    #endregion
    #region Remove Public IPs
    if($PublicIP -ne $null)
    {
        try
        {
            Remove-AzureRmResource -ResourceId $PublicIP.Id -Force -ErrorAction Stop | Out-Null
            $hash.PublicIpStatus = "Deleted"
        }
        catch
        {
            $hash.PublicIpStatus = "Failed to Delete"
        }
    }
    else
    {
        $hash.PublicIpStatus = "N/A"
    }
#endregion
    #region Disable Backups
    $vaults = Get-AzureRmRecoveryServicesVault -ResourceGroupName $ResourceGroupName
    if($vaults -ne $null)
    {
        foreach ($v in $vaults)
        {
            Set-AzureRmRecoveryServicesVaultContext -Vault $v | Out-Null
            $Vms = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM
            if($Vms -ne $null)
            {
                foreach($vmBackup in $Vms)
                {
                    if($vmBackup.FriendlyName -match $VMName)
                    {
                        $backupitem = Get-AzureRmRecoveryServicesBackupItem -Container $vmBackup -WorkloadType AzureVM
                        try
                        {
                            Disable-AzureRmRecoveryServicesBackupProtection -Item $backupitem -Force -ErrorAction Stop | Out-Null
                            $hash.BackupItemName = $vmBackup.FriendlyName
                            $hash.BackupItemStatus = 'Disabled'
                        }
                        catch
                        {
                            $hash.BackupItemName = $vmBackup.FriendlyName
                            $hash.BackupItemStatus = 'Failed to Disable'
                        }
                    }
                }
            }
        }
    }
#endregion
    #region Remove from Automation Accounts(Patching and other System Groups)
    $AutomationAccounts = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName
    foreach ($Account in $AutomationAccounts)
    {
        $Workers = $Account | Get-AzureRmAutomationHybridWorkerGroup
        foreach ($worker in $Workers)
        {
            if (($worker.GroupType -eq 'System') -and ($worker.RunbookWorker.name -match $VmName))
            {
                $worker | Remove-AzureRmAutomationHybridWorkerGroup
            }
        }
    }
#endregion
    #region Remove Boot Diagnostics
    if($vm.DiagnosticsProfile.bootDiagnostics.storageUri -ne $null)
    {
        try
        {
            $StorageAccName = $vm.DiagnosticsProfile.bootDiagnostics.storageUri.Replace('https://','').Split('.')[0]
            $StorageAcc = Get-AzureRmStorageAccount -Name $StorageAccName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
            $ContainerName = Get-AzureStorageContainer -Name "bootdiagnostics-$($vmname.ToLower())-*" -Context $StorageAcc.Context.Context -ErrorAction Stop
            Remove-AzureStorageContainer -Name $ContainerName.Name -Force -PassThru -Context $StorageAcc.Context.Context -ErrorAction Stop | Out-Null
            $hash.BootDiagnosticsContainerName = $ContainerName.Name
            $hash.BootDiagnosticsContainerStatus = "Deleted Sucessfully"
        }
        catch
        {
            $hash.BootDiagnosticsContainerStatus = "Failed to Delete"
        }
    }
#endregion
    if ($FunctionLogin)
    {
        Write-Verbose "Function login present. Logout in progress..."
        Disconnect-AzureRmAccount -Scope Process | Out-Null
    }
    return ($hash | ConvertTo-Json -Depth 10)
}

function New-AzureRMVMFull
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        #Azure Credentials
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Parameter Set 1')]
        [pscredential]
        $Credential,

        #Azure SubscriptionId
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateScript({[guid]::parse($_)})]
        [guid]
        $SubscriptionId,

        # Azure RM Location
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] 
        $Location,

        # Azure RM Resource Group Name
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=3,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ResourceGroup,

        # Azure RM Availability Set ID
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=4,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $AvailabilitySetID,

        # Azure RM Disk Type
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=5,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Premium_LRS", "StandardSSD_LRS", "Standard_LRS")]
        [string]
        $OsDiskTypeId,
        
        # Azure RM Storage Account Blob Endpoint
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=6,
                   ParameterSetName='Parameter Set 1')]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $StorageAccountBlobEndpoint,
              
        # Azure RM VMNet Subnet ID
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=7,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetID,
        
        # Azure RM Network Security Group ID 
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=8,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $NetworkSecurityGroupId,
        
        # Create New Public IP
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=9,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $PublicIp = 'true',
        
        # Azure RM Vm SKU
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=10,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VmSize,
        
        # Vm Hostname
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=11,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Hostname,
        
        # Azure RM Image SKU
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=12,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ImageId,
        
        # Use Own Enterprise License
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=13,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $OwnLicense = 'false',
        
        # VM OS Type
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=14,
                   ParameterSetName='Parameter Set 1')]
        [ValidateSet("Windows", "Linux")]
        [string]
        $OsType,
        
        # Enable Boot Diagnostics
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=15,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $BootDiagnostics = 'true',
        
        # Register VM in Azure AD
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=16,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $RegisterAzureAD = 'false',
        
        # Enable Anti Malware Extension
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=17,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $AntiMalware = 'true',
        
        # Azure RM Data Disk 1
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=18,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Disk1 = 'null',
        
        # Azure RM Data Disk 2
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=19,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Disk2= 'null',
        
        # Azure RM Data Disk 3
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=20,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Disk3 = 'null',
        
        # Azure RM Data Disk 4
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=21,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Disk4 = 'null',
        
        # Azure RM Data Disk 5
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=22,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Disk5 = 'null',

        # Turn on Patching
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=23,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigureUpdates = $false,

        # Automation Account Name for Patching
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=24,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $AutomationAccountName = 'null',

        # Workspace Account Name for Patching
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=25,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $WorkSpaceName = 'null',

        # Turn on Backups
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=26,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigureBackups = $false,

        # Workspace Account Name for Patching
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=27,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultID = 'null',

        # Workspace Account Name for Patching
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=28,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $BackupPolicyName = 'null',

        # Open HPSA Ports for Agent Deployment
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=29,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $OpenHpsaPorts = 'false'

    )
    if($psBoundParameters['verbose'])
    {
        $VerbosePreference = "Continue"
    }
    if (!(Get-AzureRmContext))
    {
        try
        {
            Write-Verbose "No Azure RM Context found. Attempting to login..."
            Connect-AzureRmAccount -Credential $Credential -Subscription $Subscriptionid -Scope Process -ErrorAction Stop
            Write-Verbose "Logging into Azure Subscription $SubscriptionId"
        }
        catch
        {
            Write-Error 'No Azure RM Context found. Run Connect-AzureRMAccount before running this command or provide valid values for Credential and SubscriptionId parameters' -RecommendedAction 'Please authenticate via Connect-AzureRMAccount'
            return
        }
    }
    else
    {
        Write-Verbose "Azure RM Context present. Continuing"
    }
    Write-Verbose "Creating random password"
    $vmpassword = Get-RandomPassword -Length 10
    Write-Verbose "Creating credentials"
    $vmcreds = [pscredential]::new('TssaAdmin',($vmpassword | ConvertTo-SecureString -AsPlainText -Force))
    Write-Verbose "Checking Storage Account Blob Endpoint"
    if($StorageAccountBlobEndpoint -ne 'null')
    {
        $storageaccountname = $StorageAccountBlobEndpoint.Substring(0,($StorageAccountBlobEndpoint.IndexOf('.'))).Replace('https://','')
        Write-Verbose "Retrieving Storage Account details for $storageaccountname"
        $sgt = (Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $storageaccountname -ErrorAction Stop).Sku.Tier
    }
    #region Create the VM object
    Write-Verbose "Creating VM Object"
    $expression = "New-AzureRmVMConfig -VMName $hostName -VMSize $VMSize"
    if($AvailabilitySetID -ne 'null')
    {
        $expression += " -AvailabilitySetId $AvailabilitySetID"
    }
    if($RegisterAzureAD -eq 'true')
    {
        $expression += " -IdentityType 'SystemAssigned'"
    }
    if($OwnLicense -eq 'true')
    {
        $expression +=  " -LicenseType 'Windows_Server'"
    }
    $vmConfig = Invoke-Expression -Command $expression
    if($OsType -eq 'Windows')
    {
        Set-AzureRmVMOperatingSystem -VM $vmConfig -Windows -ComputerName $Hostname -Credential $vmcreds -ProvisionVMAgent -EnableAutoUpdate -ErrorAction Stop | Out-Null
        Set-AzureRmVMSourceImage -VM $vmConfig -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus $ImageId -Version latest -ErrorAction Stop | Out-Null
    }
    else
    {
        if ($FunctionLogin)
        {
            Write-Verbose "Function login present. Logout in progress..."
            Disconnect-AzureRmAccount -Scope Process | Out-Null
        }
        throw 'Non-windows Currently not available'
        return;
    }
    $adisks = Get-Variable -Name disk*
#endregion
    #region Managed Disks: If managed, set the type of disk chosen else, set the storage to Storage account based on the Disk code chosen. Choose storage account to use if applicable.
    switch ($StorageAccountBlobEndpoint)
    {
        'null' {
                    Write-Verbose "Configuring OS Disk on VMObject"  
                    Set-AzureRmVMOSDisk -VM $vmConfig -StorageAccountType $OsDiskTypeId -CreateOption FromImage -Windows -ErrorAction Stop | Out-Null
                    for ($i=0;$i -lt $adisks.Count;$i++)
                    {
                        if(($adisks[$i].Value -ne 0) -and ($adisks[$i].Value -ne 'null'))
                        {
                            Write-Verbose "Adding data disks to VM Object"
                            Add-AzureRmVMDataDisk -CreateOption Empty -Lun $i -VM $vmConfig -DiskSizeInGB $adisks[$i].Value -Name "$Hostname-$($adisks[$i].Name)" -StorageAccountType $OsDiskTypeId -Caching None -ErrorAction Stop | Out-Null
                        }
                    }
                }
        default {
                    Write-Verbose "Configuring OS Disk on VMObject"
                    $storageuri = "$($StorageAccountBlobEndpoint)vhds/$Hostname/$Hostname-OSDisk.vhd"
                    Set-AzureRmVMOSDisk -VM $vmConfig -Name $hostName -Windows -VhdUri $storageuri -CreateOption FromImage -ErrorAction Stop | Out-Null
                    for ($i=0;$i -lt $adisks.Count;$i++)
                    {
                        if(($adisks[$i].Value -ne 0) -and ($adisks[$i].Value -ne 'null'))
                        {
                            $dduri = "$($StorageAccountBlobEndpoint)vhds/$Hostname/$Hostname-$($adisks[$i].Name).vhd"
                            Write-Verbose "Adding data disks to VM Object"
                            Add-AzureRmVMDataDisk -VM $vmConfig -Name "$Hostname-$($adisks[$i].Name)" -DiskSizeInGB $adisks[$i].Value -VhdUri $dduri -CreateOption Empty -Lun $i -Caching None -ErrorAction Stop | Out-Null
                        }
                    }
                }
    }
#endregion
    #region Boot Diagnostics
    Set-AzureRmVMBootDiagnostics -VM $vmConfig -Disable -ErrorAction Stop | Out-Null
    if ($BootDiagnostics -eq 'true')
    {
        Write-Verbose "Enabling VM Diagnostics"
        $vmConfig.DiagnosticsProfile.BootDiagnostics.Enabled = $true
        if(($StorageAccountBlobEndpoint -ne 'null') -and ($sgt -eq 'Standard'))
        {
            $vmConfig.DiagnosticsProfile.BootDiagnostics.StorageUri = $StorageAccountBlobEndpoint
        }
        else
        {
            $vmConfig.DiagnosticsProfile.BootDiagnostics.StorageUri = (Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction Stop | Where-Object {($_.Sku.Tier -eq 'Standard') -and ($_.Location -eq $Location)})[0].PrimaryEndpoints.Blob
        }
    }
    else
    {
        $vmConfig.DiagnosticsProfile.BootDiagnostics.Enabled = $false
        $vmConfig.DiagnosticsProfile.BootDiagnostics.StorageUri = $null
    }
#endregion
    #region Public IP & Create NIC.
    switch($PublicIp)
    {
        {$_ -eq 'true'} {
                            Write-Verbose "Creating Public IP"
                            $Npublicip = New-AzureRmPublicIpAddress `
                                            -Name "$Hostname-PIP" `
                                            -ResourceGroupName $ResourceGroup `
                                            -Location $Location -Sku Basic `
                                            -AllocationMethod Dynamic `
                                            -IpAddressVersion IPv4 -ErrorAction Stop -Force
                            Write-Verbose "Creating NIC"
                            $nic = New-AzureRmNetworkInterface `
                                        -Name "$Hostname-NIC" `
                                        -ResourceGroupName $ResourceGroup `
                                        -Location $Location `
                                        -SubnetId $SubnetID `
                                        -NetworkSecurityGroupId $NetworkSecurityGroupId `
                                        -PublicIpAddressId $NPublicIp.Id `
                                        -Force -ErrorAction Stop
                        }
        {$_ -eq 'false'} {
                            Write-Verbose "Creating NIC"
                            $nic = New-AzureRmNetworkInterface `
                                    -Name "$Hostname-NIC" `
                                    -ResourceGroupName $ResourceGroup `
                                    -Location $Location `
                                    -SubnetId $SubnetID `
                                    -NetworkSecurityGroupId $NetworkSecurityGroupId `
                                    -Force -ErrorAction Stop
                        }
    }
    Write-Verbose "Adding NIC to VMObject"
    Add-AzureRmVMNetworkInterface -VM $vmConfig -Id $nic.Id -ErrorAction Stop | Out-Null
#endregion
    #region Build and configure VM
    try
    {
        Write-Verbose "Starting VM Build"
        $job = New-AzureRmVM -ResourceGroupName $ResourceGroup -Location $Location -VM $VMConfig -ErrorAction Stop -AsJob
        Wait-Job -Job $job -Timeout 3600
        Receive-Job -Job $job | Out-Null
        Write-Verbose "VM $Hostname created sucessfully." 
        #Antivirus / Antimalware
        if($AntiMalware -eq 'true')
        {
            Write-Verbose "Adding Antimalware to $Hostname..."
            Add-AzureRmVmAntimalware -ResourceGroupName $ResourceGroup -VmName $Hostname -ErrorAction Stop
        }
        #Open HPSA Ports
        if ($OpenHpsaPorts -eq 'true')
        {
            Write-Verbose 'Opening local firewall ports for HPSA deployment'
            $scriptpath = New-TempHpsaOpenPortScript
            Invoke-AzureRmVMRunCommand -ResourceGroupName $ResourceGroup -VMName $Hostname -CommandId RunPowerShellScript -ScriptPath $scriptpath -ErrorAction Stop
            Remove-Item -Path $scriptpath -Force
        }
        #Configure Patching
        if($ConfigureUpdates -eq 'true')
        {
            Write-Verbose "Adding machine to Azure Update Management"
            Add-AzureRMVMUpdateManagementConfig -VmName $Hostname -ResourceGroupName $ResourceGroup -WorkSpaceName $WorkSpaceName -AutomationAccountName $AutomationAccountName -ErrorAction Stop
        }
        #Enable Backups
        if ($ConfigureBackups -eq 'true')
        {
            Write-Verbose "Configuring Backup"
            Enable-AzureRmVmBackup -ResourceGroup $ResourceGroup -VMName $Hostname -PolicyName $BackupPolicyName -VaultID $VaultID -ErrorAction Stop
        }
        Write-Verbose "Retrieving machine config..."
        $vm = Get-AzureRMVM -ResourceGroupName $ResourceGroup -Name $Hostname -ErrorAction Stop
        $vm.OSProfile.AdminPassword = $vmpassword
        return ($vm | ConvertTo-Json -Depth 100)
    }
    catch #Catch all failures and rollback.
    {
        if (Get-AzureRmVm -ResourceGroupName $ResourceGroup -Name $Hostname)
        {
            Delete-AzureRMVMFull -ResourceGroupName $ResourceGroup -VmName $Hostname
        }
        else
        {
            Remove-AzureRmNetworkInterface -Force -Name $nic.Name -ResourceGroupName $nic.ResourceGroupName -AsJob | Out-Null
            if($Npublicip)
            {
                $Npublicip | Remove-AzureRmPublicIpAddress -Force -AsJob | Out-Null
            }
        }
        throw $Error[0]
        return
    }
#endregion
}