function SplitText($String)
{
    #This is to seperate title cased strings to a sentence. eg. SplitText('WhatTheF***')
    [Regex]::Split($String,("(?<!^)(?=[A-Z])"))
}

function Get-AzureAvailableResources()
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
    Login-AzureRmAccount -Credential $Credential -ErrorAction Stop -Verbose | Out-Null

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
                                                if(($vmsize.LocationInfo.Zones.Count) -ge 3){$RegionSupportsHA = 'true'}
                                                [ordered]@{
                                                            #VMSize Properties
                                                            name = $vmsize.Name
                                                            id = $vmsize.Name
                                                            vCPU = ($vmsize.Capabilities | Where {$_.name -Match 'vCPUs'}).Value
                                                            MemoryGB = ($vmsize.Capabilities | Where {$_.name -Match 'MemoryGB'}).Value
                                                            OSVhdSizeMB = ($vmsize.Capabilities | Where {$_.name -Match 'OSVhdSizeMB'}).Value
                                                            TempStorageMB = ($vmsize.Capabilities | Where {$_.name -Match 'MaxResourceVolumeMB'}).Value
                                                            MaxDataDiskCount = ($vmsize.Capabilities | Where {$_.name -Match 'MaxDataDiskCount'}).Value
                                                            PremiumStorageSupport = ($vmsize.Capabilities | Where {$_.name -Match 'PremiumIO'}).Value
                                                            LowPriorityCapable = ($vmsize.Capabilities | Where {$_.name -Match 'LowPriorityCapable'}).Value
                                                            HighAvailability = if(($vmsize.LocationInfo.Zones.Count) -ge 3){$vmsize.LocationInfo.Zones}else{"Not available"}
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
    Disconnect-AzureRmAccount -Verbose | Out-Null
    $json = @{"Locations" = $CustomObject} | ConvertTo-Json -Depth 100 -Verbose
    return $json
}

function Get-AzureClientResources()
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
    Login-AzureRmAccount -Credential $Credential -ErrorAction Stop -Force -verbose | Out-Null
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
                                                                                    id = $_.Id
                                                                                    ScheduleRunDays = $_.SchedulePolicy.ScheduleRunDays | %{$_}
                                                                                    ScheduleRunTimes = $_.SchedulePolicy.ScheduleRunTimes | %{if($_){"$($_.ToString()) SAST"}}
                                                                                    ScheduleRunFrequency = $_.SchedulePolicy.ScheduleRunFrequency
                                                                                    IsDailyScheduleEnabled = $_.RetentionPolicy.IsDailyScheduleEnabled
                                                                                    IsWeeklyScheduleEnabled = $_.RetentionPolicy.IsWeeklyScheduleEnabled
                                                                                    IsMonthlyScheduleEnabled = $_.RetentionPolicy.IsMonthlyScheduleEnabled
                                                                                    IsYearlyScheduleEnabled = $_.RetentionPolicy.IsYearlyScheduleEnabled
                                                                                    DailyScheduleDurationCountInDays = $_.RetentionPolicy.DailySchedule.DurationCountInDays
                                                                                    DailyScheduleRetentionTimes = $_.RetentionPolicy.DailySchedule.RetentionTimes | %{if($_){"$($_.ToString()) SAST"}}
                                                                                    WeeklyScheduleDurationCountInDays = $_.RetentionPolicy.WeeklySchedule.DurationCountInDays
                                                                                    WeeklyScheduleRetentionTimes = $_.RetentionPolicy.WeeklySchedule.RetentionTimes  | %{if($_){"$($_.ToString()) SAST"}}
                                                                                    MonthlyScheduleDurationCountInDays = $_.RetentionPolicy.MonthlySchedule.DurationCountInDays
                                                                                    MonthlyScheduleRetentionTimess = $_.RetentionPolicy.MonthlySchedule.RetentionTimess  | %{if($_){"$($_.ToString()) SAST"}}
                                                                                    YearlyScheduleDurationCountInDays = $_.RetentionPolicy.YearlySchedule.DurationCountInDays
                                                                                    YearlyScheduleRetentionTimes = $_.RetentionPolicy.YearlySchedule.RetentionTimes  | %{if($_){"$($_.ToString()) SAST"}}
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
                                                        -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | Where {$_.VirtualMachine -eq $null}|
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
                                                -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose | Where {$_.IpConfiguration -eq $null} |
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
                                                -ResourceGroupName $ResourceGroup.ResourceGroupName -verbose |
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
    #Disconnect-AzureRmAccount -verbose | Out-Null
    $Tenants = @{
                    Tenants = $TennantArray
            }
    $data = $Tenants | ConvertTo-Json -Depth 100 -verbose
    Return $data
}

function Get-RandomPassword([int]$Length=10)
{
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

function New-AzureRMVMFull ()
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
        [Parameter(Mandatory=$true, 
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
        [Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
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
        $RegisterAzureAD = 'true',
        
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
        $Disk5 = 'null'
    )


    function Add-AzureRmVmAntimalware($ResouceGroupName,$VMName)
    {
    try
    {
        $Location = Get-AzureRmVM -ResourceGroupName $ResouceGroupName -Name $VMName -ErrorAction Stop
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
            -ResourceGroupName $ResouceGroupName `
            -ExtensionType $av.Type `
            -Publisher $av.PublisherName `
            -Location $av.Location `
            -Name $AV.Type `
            -Settings @{"AntimalwareEnabled" = "true"} `
            -TypeHandlerVersion $avversion `
            -ErrorAction Stop -AsJob
        Wait-Job -Job $job -Timeout 3600
        Receive-Job -Job $job >> C:\Windows\Temp\AzureError.txt
    }
    catch
    {
        throw $Error[0]
    }
}

    Login-AzureRmAccount -Credential $Credential -ErrorAction Stop | Out-Null
    Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop -Scope Process | Out-Null
    $vmpassword = Get-RandomPassword -Length 10
    $vmcreds = [pscredential]::new('TssaAdmin',($vmpassword | ConvertTo-SecureString -AsPlainText -Force))
    if($StorageAccountBlobEndpoint -ne 'null')
    {
        $storageaccountname = $StorageAccountBlobEndpoint.Substring(0,($StorageAccountBlobEndpoint.IndexOf('.'))).Replace('https://','')
        $sgt = (Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $storageaccountname -ErrorAction Stop).Sku.Tier
    }

    #Create the VM object
    $expression = "New-AzureRmVMConfig -VMName $hostName -VMSize $VMSize"
    if($AvailabilitySetID -ne 'null'){$expression += " -AvailabilitySetId $AvailabilitySetID"}
    #if($RegisterAzureAD -eq 'true'){$expression += " -IdentityType 'SystemAssigned'"}
    if($OwnLicense -eq 'true'){$expression +=  " -LicenseType 'Windows_Server'"}
    $vmConfig = Invoke-Expression -Command $expression
    if($OsType -eq 'Windows')
    {
        Set-AzureRmVMOperatingSystem -VM $vmConfig -Windows -ComputerName $Hostname -Credential $vmcreds -ProvisionVMAgent -EnableAutoUpdate -ErrorAction Stop | Out-Null
        Set-AzureRmVMSourceImage -VM $vmConfig -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus $ImageId -Version latest -ErrorAction Stop | Out-Null
    }
    else
    {
        #Disconnect-AzureRmAccount | Out-Null
        throw 'Non-windows Currently not available'
        Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
    }
    $adisks = Get-Variable -Name disk*

    #If managed, set the type of disk chosen else, set the storage to Storage account based on the Disk code chosen. Choose storage account to use if applicable.
    switch ($StorageAccountBlobEndpoint)
    {
        'null' {  
                    Set-AzureRmVMOSDisk -VM $vmConfig -StorageAccountType $OsDiskTypeId -CreateOption FromImage -Windows -ErrorAction Stop | Out-Null
                    for ($i=0;$i -lt $adisks.Count;$i++)
                    {
                        if(($adisks[$i].Value -ne 0) -and ($adisks[$i].Value -ne 'null'))
                        {
                            Add-AzureRmVMDataDisk -CreateOption Empty -Lun $i -VM $vmConfig -DiskSizeInGB $adisks[$i].Value -Name "$Hostname-$($adisks[$i].Name)" -StorageAccountType $OsDiskTypeId -Caching None -ErrorAction Stop | Out-Null
                        }
                    }
                }
        default {
                    $storageuri = "$($StorageAccountBlobEndpoint)vhds/$Hostname/$Hostname-OSDisk.vhd"
                    Set-AzureRmVMOSDisk -VM $vmConfig -Name $hostName -Windows -VhdUri $storageuri -CreateOption FromImage -ErrorAction Stop | Out-Null
                    for ($i=0;$i -lt $adisks.Count;$i++)
                    {
                        if(($adisks[$i].Value -ne 0) -and ($adisks[$i].Value -ne 'null'))
                        {
                            $dduri = "$($StorageAccountBlobEndpoint)vhds/$Hostname/$Hostname-$($adisks[$i].Name).vhd"
                            Add-AzureRmVMDataDisk -VM $vmConfig -Name "$Hostname-$($adisks[$i].Name)" -DiskSizeInGB $adisks[$i].Value -VhdUri $dduri -CreateOption Empty -Lun $i -Caching None -ErrorAction Stop | Out-Null
                        }
                    }
                }
    }

    #Boot Diagnostics
    Set-AzureRmVMBootDiagnostics -VM $vmConfig -Disable -ErrorAction Stop | Out-Null
    if ($BootDiagnostics -eq 'true')
    {
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

    #Public IP & Create NIC.
    switch($PublicIp)
    {
        {$_ -eq 'true'} {
                        $Npublicip = New-AzureRmPublicIpAddress `
                                        -Name "$Hostname-PIP" `
                                        -ResourceGroupName $ResourceGroup `
                                        -Location $Location -Sku Basic `
                                        -AllocationMethod Dynamic `
                                        -IpAddressVersion IPv4 -ErrorAction Stop -Force
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
                            $nic = New-AzureRmNetworkInterface `
                                    -Name "$Hostname-NIC" `
                                    -ResourceGroupName $ResourceGroup `
                                    -Location $Location `
                                    -SubnetId $SubnetID `
                                    -NetworkSecurityGroupId $NetworkSecurityGroupId `
                                    -Force -ErrorAction Stop
                        }
    }

    Add-AzureRmVMNetworkInterface -VM $vmConfig -Id $nic.Id -ErrorAction Stop | Out-Null
    #Build the VM
    try
    {
        $job = New-AzureRmVM -ResourceGroupName $ResourceGroup -Location $Location -VM $VMConfig -ErrorAction Stop -AsJob
        Wait-Job -Job $job -Timeout 3600
        Receive-Job -Job $job
        Write-Verbose "$Hostname created sucessfully." -Verbose
        #Antivirus / Antimalware
        if($AntiMalware -eq 'true')
        {
            Add-AzureRmVmAntimalware -ResouceGroupName $ResourceGroup -VMName $Hostname | Out-Null
            if($?){Write-Verbose "AV Sucessfully added to VM." -Verbose}
        }
        $vm = Get-AzureRMVM -ResourceGroupName $ResourceGroup -Name $Hostname
        #Disconnect-AzureRmAccount | Out-Null
        $vm.OSProfile.AdminPassword = $vmpassword
        return ($vm | ConvertTo-Json -Depth 100)
    }
    catch #Catch all failures and rollback.
    {
        Remove-AzureRmNetworkInterface -Force -Name $nic.Name -ResourceGroupName $nic.ResourceGroupName -AsJob | Out-Null
        if($PublicIp -eq 'true')
        {
            Remove-AzureRmPublicIpAddress -Force -Name $Npublicip.Name -ResourceGroupName $Npublicip.ResourceGroupName -AsJob | Out-Null
        }
        #Disconnect-AzureRmAccount | Out-Null

    }
    Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
}

function Delete-AzureRMVMFull($SubscriptionId,$ResourceGroupName,$VMName,$Credential)
{
    Login-AzureRmAccount -Credential $Credential -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    #region Get VM Resources
$VM = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
$Nic = Get-AzureRmResource -ResourceId $Vm.NetworkProfile.NetworkInterfaces.Id -ExpandProperties -ErrorAction Stop
try
{
    $PublicIP = Get-AzureRMResource -ResourceId $nic.Properties.ipConfigurations.properties.publicIPAddress.id -ExpandProperties -ErrorAction Stop
}
catch
{
        $PublicIP = 'N/A'
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
    return ($hash | ConvertTo-Json)
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
    return ($hash | ConvertTo-Json)
}
#endregion
    #region Remove Storage
if($vm.StorageProfile.OsDisk.Vhd.Uri -ne $null)
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
            #
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
    return ($hash | ConvertTo-Json -Depth 10)
}

function New-DynamicSearchFilter
{
    <#
    .Synopsis
    Dynamic Search Filter Creator for Multiple Arguments
    .DESCRIPTION

    This function builds a Dynamic Search Filter string for Powershell filters within If Statements or Where statements. Instead of builing multiple ifs within a statement, let Powershell do it for you :)
    
    This is usefull in orchestration environments where the string get's created from a different output.
    .
    .EXAMPLE

        $Value = New-DynamicSearchFilter -PowershellProperty '$_.Name' -SubComparisonOperator '-match' -ComparisonOperator '-or' -String 'BITS,WORKSTATION,SPOOLER,SECLOGON'

        $Value = ($_.Name -match 'BITS') -or ($_.Name -match 'WORKSTATION') -or ($_.Name -match 'SECLOGON')     

        Get-Service | Where ([scriptblock]::Create($Value))

        Status   Name               DisplayName                           
        ------   ----               -----------                           
        Stopped  BITS               Background Intelligent Transfer Ser...
        Running  LanmanWorkstation  Workstation                           
        Stopped  seclogon           Secondary Logon 

    .OUTPUTS
    [String] object
    #>
    [CmdletBinding(DefaultParameterSetName='Main Set 0', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.ExchangeSA.co.za/ -or Jordach.Singh@ExchangeSA.co.za',
                  ConfirmImpact='Low')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Input Powershell Pipline Character or Property as a plain string with single quotes. Eg.: '$_' or '$_.Property1' or '$_.Name' etc.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=0,ParameterSetName='Main Set 0')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=0,ParameterSetName='Main Set 1')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=0,ParameterSetName='Main Set 2')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $PowershellProperty,

        # Input Powershell Comparison Operator as a plain string with single quotes and no spaces. Eg.: '-and' or '-or' or '-match' etc. This will form part of the inner expression.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=1,ParameterSetName='Main Set 0')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=1,ParameterSetName='Main Set 1')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=1,ParameterSetName='Main Set 2')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubComparisonOperator,

        # Input Powershell Comparison Operator as a plain string with single quotes and no spaces. Eg.: '-and' or '-or' or '-match' etc. This will form part of the outer expression.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=2,ParameterSetName='Main Set 0')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=2,ParameterSetName='Main Set 1')]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=2,ParameterSetName='Main Set 2')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComparisonOperator,

        # Input Powershell data as a plain comma seperated string with single quotes. Eg.: 'value1,value2,value3'. This will form part of value for each inner expression. In the examplem there will be 3 comparisons done.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=3,ParameterSetName='Main Set 0')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $String,

        # Input Powershell data as an string array object. Eg.: @('value1','value2','value3') etc. This will form part of value for each inner expression. In the examplem there will be 3 comparisons done.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=3,ParameterSetName='Main Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [array]
        $StringArray,

        # Input Powershell data as an integer array object. Eg.: @(7,25,9,989,12) etc. This will form part of value for each inner expression. In the examplem there will be 5 comparisons done.
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false,ValueFromRemainingArguments=$false,Position=3,ParameterSetName='Main Set 2')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [array]
        $IntArray
    )

    if ($String)
    {
        $stringarr = $string.Split(',')
    }
    elseif($IntArray)
    {
        [array]$stringarr = $IntArray
    }
    elseif($StringArray)
    {
        [array]$stringarr = $StringArray
    }

        $newstring = ''
    if ($stringarr.Count -gt 1)
    {
        for ($i = 0; $i -lt ($stringarr.Count - 1); $i++)
        {
            if (($stringarr[$i]).getType() -eq [string])
            {
                $newstring += "($PowershellProperty $SubComparisonOperator '$($stringarr[$i])') $ComparisonOperator "
            }
            else
            {
                $newstring += "($PowershellProperty $SubComparisonOperator $($stringarr[$i])) $ComparisonOperator "
            }
        }
        if (($stringarr[$i]).getType() -eq [string])
        {
            $newstring += "($PowershellProperty $SubComparisonOperator '$($stringarr[-1])')"
        }
        else
        {
            $newstring += "($PowershellProperty $SubComparisonOperator $($stringarr[-1]))"
        }
    }
    elseif ($stringarr.Count -eq 1)
    {
       "($PowershellProperty $SubComparisonOperator $($stringarr[-1]))" 
    }
    return $newstring
}

function Get-VMWareSerialNumber($UUID)
{
    $uuid = $uuid.Replace('-','')
    $sn = ''
    for ($i=0;$i -lt $uuid.Length; $i+=2)
    {
        $sn += $uuid.Substring($i,2)
        $sn += ' '
    }
    $str1 = $sn.Substring(0,23)
    $str2 = $sn.Substring(24)
    $sn = ("VMWARE-$str1-$str2").ToUpper()
    return $sn
}

function Get-VmwareVmToolStatus($VC,$UserName,$Password,$serversToSkip)
{
    try
    {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -ProxyPolicy NoProxy -ParticipateInCeip:$false -Confirm:$false -ErrorAction Stop | Out-Null
        Connect-VIServer $VC -Username $UserName -Password $Password -ErrorAction Stop | Out-Null
        Write-Verbose "trying $vc" -Verbose
        $VMObjects = Get-VM -ea Stop
        $newobj = $VMObjects | ? {(($_.ExtensionData.Summary.Guest.ToolsVersionStatus -match 'guestToolsNeedUpgrade') -or ($_.ExtensionData.Summary.Guest.ToolsVersionStatus -match 'guestToolsNotInstalled'))} |
                    Select  @{n='HostName';e={$_.Guest.HostName}},
                    Name,
                    @{n='UUID';e={$_.ExtensionData.Summary.Config.UUID}},
                    @{n='SerialNumber';e={Get-VMWareSerialNumber -UUID $_.ExtensionData.Summary.Config.UUID}},
                    @{n='HardwareVersion';e={$_.Version}},
                    @{n='ToolsVersion';e={($_ | Get-VMGuest).ToolsVersion}},
                    @{n='ToolsStatus';e={(SplitText($_.ExtensionData.Guest.ToolsStatus)) -join ' '}},
                    @{n='ToolsRunningStatus';e={(SplitText($_.ExtensionData.Guest.ToolsRunningStatus)) -join ' '}}
        Disconnect-VIServer $vc -Confirm:$false -Force | Out-Null
        if($serversToSkip)
        {
            $searchblock = New-DynamicSearchFilter -PowershellProperty '$_.Name' -SubComparisonOperator '-notmatch' -ComparisonOperator '-and' -String $serversToSkip
            return ($newobj | ? ([scriptblock]::Create($searchblock)))
        }
        else
        {
            return $newobj
        }
    }
    catch
    {
        Write-Verbose "failed to connect to $vc" -Verbose
    }
}