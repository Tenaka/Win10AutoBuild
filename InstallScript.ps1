<#
########################################################################################
###########################  WINDOWS 10 MEDIA PREP  ####################################
########################################################################################
Download and mount Windows 10 iso
Copy to local drive then
split install.wim into 2gb files to support Fat32, required for usb boot devices

Dism /Split-Image /ImageFile:C:\Downloads\Window21H2\sources\install.wim /SWMFile:C:\Downloads\Window21H2\sources\install.swm /FileSize:2000

Remove the install.wim 
Copy the entire contents to the root of the USB Pen

Note: During install Windows will request username - the default is fauxadmin, Password1234
The username and password is hardcoded into the installScript.ps1, they need to match for autologon to work.

########################################################################################
################################  AUTOUNATTEND.XML  ####################################
########################################################################################
Copy the following AutoUnattend.xml and copy to root of USB

<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <ImageInstall>
                <OSImage>
                    <WillShowUI>OnError</WillShowUI>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>3</PartitionID>
                    </InstallTo>
                    <InstallFrom>
                        <Path>install.swm</Path>
                        <MetaData>
                            <Key>/IMAGE/INDEX</Key>
                            <Value>1</Value>
                        </MetaData>
                    </InstallFrom>
                </OSImage>
            </ImageInstall>
            <ComplianceCheck>
                <DisplayReport>OnError</DisplayReport>
            </ComplianceCheck>
            <UserData>
                <AcceptEula>true</AcceptEula>
                <ProductKey>
                    <Key></Key>
                </ProductKey>
            </UserData>
            <DiskConfiguration>
                <WillShowUI>Always</WillShowUI>
            </DiskConfiguration>
        </component>
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-GB</UILanguage>
            </SetupUILanguage>
            <InputLocale>0809:00000809</InputLocale>
            <SystemLocale>en-GB</SystemLocale>
            <UILanguage>en-GB</UILanguage>
            <UserLocale>en-GB</UserLocale>
        </component>
    </settings>
    <settings pass="generalize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DoNotCleanTaskBar>true</DoNotCleanTaskBar>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-IE-InternetExplorer" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Home_Page>www.google.co.uk</Home_Page>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>0809:00000809</InputLocale>
            <SystemLocale>en-GB</SystemLocale>
            <UILanguage>en-GB</UILanguage>
            <UserLocale>en-GB</UserLocale>
        </component>
        <component name="Microsoft-Windows-TapiSetup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <TapiConfigured>0</TapiConfigured>
            <TapiUnattendLocation>
                <AreaCode>""</AreaCode>
                <CountryOrRegion>1</CountryOrRegion>
                <LongDistanceAccess>9</LongDistanceAccess>
                <OutsideAccess>9</OutsideAccess>
                <PulseOrToneDialing>1</PulseOrToneDialing>
                <DisableCallWaiting>""</DisableCallWaiting>
                <InternationalCarrierCode>""</InternationalCarrierCode>
                <LongDistanceCarrierCode>""</LongDistanceCarrierCode>
                <Name>Default</Name>
            </TapiUnattendLocation>
        </component>
        <component name="Microsoft-Windows-SystemRestore-Main" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DisableSR>1</DisableSR>
        </component>
    </settings>
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-PnpCustomizationsNonWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DriverPaths>
                <PathAndCredentials wcm:keyValue="1" wcm:action="add">
                    <Path>\Drivers</Path>
                </PathAndCredentials>
            </DriverPaths>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UILanguage>en-GB</UILanguage>
            <UserLocale>en-UGB</UserLocale>
            <SystemLocale>en-GB</SystemLocale>
            <InputLocale>0809:00000809</InputLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -file D:\software\InstallScript.ps1</CommandLine>
                    <Description>Application Installation</Description>
                    <Order>1</Order>
                </SynchronousCommand>
            </FirstLogonCommands>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <ProtectYourPC>1</ProtectYourPC>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
            </OOBE>
            <RegisteredOrganization>Tenaka</RegisteredOrganization>
            <RegisteredOwner>Windows User</RegisteredOwner>
            <TimeZone>GMT Standard Time</TimeZone>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="wim:c:/window10/sources/install.wim#Windows 10 Enterprise" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>

########################################################################################
###########################  SOFTWARE AND UPDATES TO INSTALL  ##########################
########################################################################################

On the local system create a Software directory and then create the following sub directories:
    "7Zip",
    "Chrome",
    "Drivers",
    "JRE",
    "MS-VS-CPlus",
    "MS-Win10-CU",
    "MS-Win10-SSU",
    "MS-Edge",
    "Notepad++",
    "TortoiseSVN"


Copy the applications to the correct directory, use the script to reference the unattended installation file type eg MS-Win10-CU is a .msu file

Add any required unzipped driver file eg .inf files to the Driver directory

Copy the Software directory with the content plus this installScript.psi to the root of the USB
Within the autounattend.xml the following line is referenced to execute the installation of updates and apps on first install

<CommandLine>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -file D:\software\InstallScript.ps1</CommandLine>

########################################################################################
##########################  DEPLOYING WINDOWS 10 #######################################
########################################################################################

Update the InstallScript.ps1 with the correct AD OU path
        $DomainN = "trg.loc"
        $ouPath = "OU=wks,OU=org,DC=trg,DC=Loc"

Pre-Create a Computer object in AD, with the planned hostname of the client being deployed.

Boot PC and enter Bios
Set UEFI to boot or intial boot to USB, F10 to save and exit
Insert USB and boot
Setup will start and prompt for disk partitioning, delete the volumes and create new
Ensure reboots into the system partition and not the USB
OK Cortana
Create a faux admin account of 'fauxadmin' + 'Password1234' - specific account and password require as its hardcoded in the script.
At initial logon the powershell will launch and will prompt for IP Addresses, hostname and domain credentials 

########################################################################################
#########################################  NOTES #######################################
########################################################################################

The unattended disk partitioning proved to be unreliable and required manual intervention

Cortana popup persists - with the SkipMachineOOBE enabled the entire wizard is hidden and is required to configure 
the 'fauxadmin' account and password for the installScript.ps1 to persist between reboots.

Yellow output, the installation has completed and written out to file, without any actual validation.


Ddism /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:d:\sources\sxs
dism /Get-WimInfo /WimFile:"C:\Downloads\Window10\sources\install.wim"
dism /Export-Image /SourceImageFile:"C:\Downloads\Window10\sources\install.wim" /SourceIndex:3 /DestinationImageFile:"C:\Downloads\Window10\sources\install_3.wim"

#>
#Confirm for elevated admin
    if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
    Write-Host "An elevated administrator account is required to run this script." -ForegroundColor Red
    }
else
{
    #C:\Software is hardcoded for scheduled tasks, update the var below, update the scheduled task as well.
    $Software = "C:\Software\"
    $check = $Software + "check.txt"

    if($psise -ne $null)
    {
        $ISEPath = $psise.CurrentFile.FullPath
        $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
        $ISEWork = $ISEPath.TrimEnd("$ISEDisp")
        $tpSoftware = Test-Path $Software
        if ($tpSoftware -eq $false)
        {
            New-Item -Path $Software -ItemType Directory -Force
            copy $ISEWork\* $Software -Recurse -Force -Verbose
        }
    }
    else
    {
        $PSWork = split-path -parent $MyInvocation.MyCommand.Path
        $tpSoftware = Test-Path $Software
        if ($tpSoftware -eq $false)
        {
            New-Item -Path $software -ItemType Directory -Force
            copy $PSWork\* $Software -Recurse -Force -Verbose
        }
      }

    $tpCheck = Test-Path -Path $check

    if ($tpCeck -eq $false)
    {
        New-Item $check -Name check.txt -ItemType File
    }
    #AutoLogon
    $adminPassword = "Password1234"
    $adminAccount = "fauxadmin"

    $adminGet = gwmi win32_useraccount | where {$_.name -eq "$adminAccount"}
    $sidGet = $adminGet.SID

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $adminAccount -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $adminPassword -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonSID -Value $sidGet -Force
    new-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 0 -PropertyType string -Force

    $tpAppScript = Get-ScheduledTask -TaskName AppScript -ErrorAction SilentlyContinue

    if ($tpAppScript -eq $false -or $tpAppScript -eq $null)
    {
        $Schedule = "APPScript"
        $allowBatt = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries 
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $adminAccount
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-executionPolicy bypass -file C:\Software\installScript.ps1'
        $principal = New-ScheduledTaskPrincipal -LogonType Interactive -UserId $adminAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $Schedule -Trigger $trigger -Settings $allowBatt -Action $action -Principal $principal
    }

    function RestartClient
    {
        shutdown /r /t 0 /f
        sleep 30
    }

########################################################################################
#################################  INSTALL DRIVERS  ####################################
########################################################################################

    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "DRIVERS111")
    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Windows Drivers were previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing  Windows Drivers" -ForegroundColor yellow
            $drvDir = $software + "Drivers\" + "*.inf" 
            & cmd /c pnputil.exe /add-driver $drvDir /subdirs /install

            Add-Content $check -Value "DRIVERS111" 
        }

########################################################################################
###################################  RENAME CLIENT  ####################################
########################################################################################
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "RENAME01")
    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Windows Service Stack was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing Windows Service Stack" -ForegroundColor yellow
            $renhn = Read-Host "Rename the client.... " 
            Rename-Computer $renhn

            Add-Content $check -Value "RENAME01" 
        }

########################################################################################
###################################  SET STATIC IP  ####################################
########################################################################################


    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "ADDY01")
    if ($InstCheck -ne $null)     
        {
            Write-Host "Looks like the IP Address was previously set" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Set a Static IP Address" -ForegroundColor yellow
            $gNetAdp = Get-NetAdapter | where {$_.Status -eq "up"}
                $intAlias = $gNetAdp.InterfaceAlias

            $gNetIPC = Get-NetIPConfiguration -InterfaceAlias $gNetAdp.Name
                $IPAddress = $gNetIPC.IPv4Address.ipaddress
                $DHCPRouter = $gNetIPC.IPv4DefaultGateway.nexthop
                $dnsAddress = $gNetIPC.dnsserver.serveraddresses

            $gNetIPC | Remove-NetIPAddress -Confirm:$false
            $gNetIPC.IPv4DefaultGateway |Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

            $IPAddress = Read-Host "Enter the Static IP"
            $DefGate = Read-Host "Enter the Default Gateway eg 192.168.0.254"
            $dnsServer = Read-Host "Enter DNS IP(s) eg 192.168.0.22 or 192.168.0.22,192.168.0.23"
            $dnsName = Read-Host "Enter an FQDN eg Contoso.net"
    
            #Set Static IP
            New-NetIPAddress -InterfaceAlias $gNetAdp.Name `
                             -IPAddress $IPAddress `
                             -AddressFamily IPv4 `
                             -PrefixLength 24 `
                             -DefaultGateway $DefGate
            #Set DNS Server                 
            Set-DnsClientServerAddress -ServerAddresses $dnsServer -InterfaceAlias $intAlias
            Add-Content $check -Value "ADDY01" 
        }

    #Reboot after hostname and IP has been set 
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "HOSTREBOOT")
    if ($InstCheck -eq $null)
    {
        Write-Host "Rebooting to apply host rename" -ForegroundColor yellow
        Add-Content $check -Value "HOSTREBOOT" 
        RestartClient
    }

########################################################################################
##################  INSTALL WINDOWS 10 SERVICING STACK UPDATE  #########################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "SSU01")
    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Windows Service Stack was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing Windows Service Stack" -ForegroundColor yellow
            $ssuDir = $software + "MS-Win10-SSU"
            $ssuGet = (ChildItem $ssuDir).FullName 
            & cmd /c wusa.exe $ssuGet /quiet

            Add-Content $check -Value "SSU01" 
        }

########################################################################################
#############  INSTALL WINDOWS 10 CUMULATIVE UPDATE  ###################################
########################################################################################
#expects only 1 CU.msu, will fail with more than one file
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "CU02")

    if ($InstCheck -ne $null )     
        {
        Write-Host "Looks like Windows Cumulative Update was previously installed" -ForegroundColor Yellow
        } 
        else
        {
            Write-Host "Installing Windows Cumulative Update, this will take a while" -ForegroundColor yellow
            $cuDir = $software + "MS-Win10-CU"
            $cuGet = (ChildItem $cuDir).FullName 
            & cmd /c wusa.exe $cuGet /quiet /norestart

            Add-Content $check -Value "CU02" 
        }

    #Check for CU installation and skip reboot 
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "CU99")
    if ($InstCheck -eq $null)
    {
        Write-Host "Rebooting to apply Windows updates" -ForegroundColor yellow
        Add-Content $check -Value "CU99" 
        RestartClient
    }
 
    #Check Windows CU Installation
    $cuDir = $software + "MS-Win10-CU"
    $cuGet = (ChildItem $cuDir).FullName 

    #List KB's installed
    $kbValue = ($cuGet | Select-String -Pattern "[A-Z]{2}\d{7}" | foreach { $_.Matches }).value
    $hotfixGet = (Get-HotFix).hotfixid
    $hotfixCount = $hotfixGet.count
    $i=0
    $cuConfirm=@()

    do
    {
    $i++  
        foreach ($hf in $hotfixGet)
        {
            if ($hf -eq $kbValue ){$cuConfirm = "cuInstalled"}
        }
    }
    until ($cuConfirm -eq "cuInstalled" -or $i -eq $hotfixCount) 

    if ($cuConfirm -eq "cuInstalled")
    {
        Write-host "Windows 10 CU has been installed" -ForegroundColor green
    }
    else
    {
    write-host "Windows 10 CU hasn't installed, confirm installation or install, then continue" -ForegroundColor RED
    pause
    }


########################################################################################
#########################  MICROSOFT OFFICE 2019 INSTALLATION  #########################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "Office19")

    if ($InstCheck -ne $null)     
        {
            Write-Host "Looks like Microsoft Office 2019 was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing MS Office 2019" -ForegroundColor yellow
            $officeDir = $software + "MS-Office2019" +"\"+ "Office"
            cd $officeDir
            $officeGet = (ChildItem $officeDir).FullName | where {$_ -like "*64.exe" }
            cmd.exe /c $officeGet
            Add-Content $check -Value "Office19" 
            #sleep 10
        }
    #may require until loop .........
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "Office19")
    if ($InstCheck -ne $true)     
        {
            Write-Host "Removing the Office C2R Client Window" -ForegroundColor yellow
            Get-Process -name OfficeC2RClient | Stop-Process
        }


    #INSTALLATION QUERY
    $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
    $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
    $getUnin = $getUninx64 + $getUninx86
    $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
    $InstallApps =@()
    
        foreach ($uninItem in $UninChild)
        {
            $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
            #Write-Host $getUninItem.DisplayName
            $UninDisN = $getUninItem.DisplayName -replace "$null",""
            $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
            $UninPub = $getUninItem.Publisher -replace "$null",""
            $UninDate = $getUninItem.InstallDate -replace "$null",""
    
            $newObjInstApps = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
            Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
            Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
            Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
            $InstallApps += $newObjInstApps
        }
        foreach ($apps in $InstallApps)
        {
            if ($apps -like "*Office 16 Click-to-Run Licensing*"){Write-Host $apps.DisplayName -ForegroundColor Green}
        }


########################################################################################
###########################  MICROSOFT VISUAL STUDIO C++ ###############################
########################################################################################
#Loop through each VS C++ installing each in turn
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "VSC99")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Visual Studio C++ was previously installed" -ForegroundColor Yellow
        }
        else
        {
            $msvscplusDir = $software + "MS-VS-CPlus"
            $msvscplusGet = (ChildItem $msvscplusDir).FullName

            foreach ($msvsplus in $msvscplusGet)
            {
            Write-Host "Installing $msvsplus Visual Studio C++" -ForegroundColor yellow
            & cmd.exe /c $msvsplus /S

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
        }
            foreach ($apps in $InstallApps)
            {
                    if ($apps -like '*C++ 2012 Redistributable (x64)*'){Write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2010 Redistributable (x64)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2013 Redistributable (x64)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2015-2022 Redistributable (x64)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2012 Redistributable (x64)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2010 Redistributable (x86)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2013 Redistributable (x86)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*C++ 2015-2022 Redistributable (x86)*'){write-Host $apps.DisplayName -ForegroundColor Green}
                }
        Add-Content $check -Value "VSC99"
            }
        }

########################################################################################
###################################  7ZIP INSTALLATION  ################################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "7Zip2107")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like 7 Zip was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing 7 Zip" -ForegroundColor yellow   
            $7zipDir = $software + "7Zip"
            $7zipGet = (ChildItem $7zipDir).FullName
            & cmd.exe /c $7zipGet /S

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*7-Zip*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }
        
            Add-Content $check -Value "7Zip2107" 
        }

        #CVE-2022-29072 - PrivEsc by dropping a crafted file on to the help, the workaround is to remove the .chm files
        Remove-Item "C:\Program Files\7-Zip\" -Filter *.chm -Recurse -force -ErrorAction SilentlyContinue
        Remove-Item "C:\Program Files (x86)\7-Zip\" -Filter *.chm -Recurse -force -ErrorAction SilentlyContinue

########################################################################################
##################################  WINSCP INSTALLATION  ###############################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "WinSCP519")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like WinSCP was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing WinSCP" -ForegroundColor yellow
            $winscpDir = $software + "WinSCP"
            $winscpGet = (ChildItem $winscpDir).FullName
            & cmd.exe /c $winscpGet /VERYSILENT /NORESTART /ALLUSERS

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*WinSCP*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }
        
            Add-Content $check -Value "WinSCP519" 
        }

########################################################################################
################################  TORTOISESVN INSTALLATION  ############################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "TortoiseSVN114")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like TortoiseSVN was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing TortoiseSVN" -ForegroundColor yellow
            $toroDir = $software + "TortoiseSVN"
            $toroGet = (ChildItem $toroDir).FullName
            & cmd.exe /c msiexec.exe /i $toroGet /qn /norestart

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*TortoiseS*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }

            Add-Content $check -Value "TortoiseSVN114" 
        }

########################################################################################
##############################  NOTEPAD PLUS PLUS INSTALLATION  ########################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "Notepad833")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Notepad ++ was previously installed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "Installing Notepad Plus Plus" -ForegroundColor yellow
            $noteDir = $software + "NotepadPlus"
            $noteGet = (ChildItem $noteDir).FullName
            & cmd.exe /c $noteGet /S

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*Notepad*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }

            Add-Content $check -Value "Notepad833" 
        }
########################################################################################
########################  MICROSOFT EDGE BROWSER INSTALLATION  #########################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "Edge99")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like MS Edge was previously installed" -ForegroundColor Yellow
        } 
        else
        {
            Write-Host "Installing MS Edge" -ForegroundColor yellow
            $edgeDir = $software + "MS-Edge"
            $edgeGet = (ChildItem $edgeDir).FullName | where {$_ -like "*.msi" }
            & cmd.exe /c msiexec.exe /i $edgeGet /norestart /quiet

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*Edge*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }
            Add-Content $check -Value "Edge99" 
        }

########################################################################################
##########################  GOOGLE CHROME BROWSER INSTALLATION  ########################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "Chrome100")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Google Chrome was previously installed" -ForegroundColor Yellow
        } 
        else
        {
            Write-Host "Installing Google Chrome" -ForegroundColor yellow
            $chromeDir = $software + "Chrome"
            $chromeGet = (ChildItem $chromeDir).FullName | where {$_ -like "*.msi" }
            & cmd.exe /c msiexec.exe /i $chromeGet /norestart /quiet

            #INSTALLATION QUERY
            $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
            $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
            $getUnin = $getUninx64 + $getUninx86
            $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
            $InstallApps =@()
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                #Write-Host $getUninItem.DisplayName
                $UninDisN = $getUninItem.DisplayName -replace "$null",""
                $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                $UninPub = $getUninItem.Publisher -replace "$null",""
                $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                $newObjInstApps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                $InstallApps += $newObjInstApps
            }
            foreach ($apps in $InstallApps)
            {
                if ($apps -like '*Chrome*'){Write-Host $apps.DisplayName -ForegroundColor Green}
            }

            Add-Content $check -Value "Chrome100" 
        }


########################################################################################
#################################  JAVA JRE INSTALLATION  ##############################
########################################################################################
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "jre8321")

    if ($InstCheck -ne $null )     
        {
            Write-Host "Looks like Java JRE was previously installed" -ForegroundColor Yellow
        }
        else
        {
            $jreDir = $software + "JRE"
            $jreGet = (ChildItem $jreDir).FullName

            foreach ($jre in $jreGet)
            {
            Write-Host "Installing Java JRE $jre" -ForegroundColor yellow
            & cmd.exe /c $jre /s

                #INSTALLATION QUERY
                $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
                $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
                $getUnin = $getUninx64 + $getUninx86
                $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
                $InstallApps=@()
    
                foreach ($uninItem in  $UninChild)
                {
                    $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue 
    
                    #Write-Host $getUninItem.DisplayName
                    $UninDisN = $getUninItem.DisplayName -replace "$null",""
                    $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
                    $UninPub = $getUninItem.Publisher -replace "$null",""
                    $UninDate = $getUninItem.InstallDate -replace "$null",""
    
                    $newObjInstApps = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
                    Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
                    Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
                    Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
                    $InstallApps += $newObjInstApps
                }
                foreach ($apps in $InstallApps)
                {
                    if ($apps -like '*Java 7 Update*'){Write-Host $apps.DisplayName -ForegroundColor Green}
                    if ($apps -like '*Java 8 Update*'){Write-Host $apps.DisplayName -ForegroundColor Green}
                }
            }

        Add-Content $check -Value "jre8321"

        }

########################################################################################
######################################  TIDY UP  #######################################
########################################################################################
    #Disable futher Autologons
    Write-Host "Disabling Autologon" -ForegroundColor yellow
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "" -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value "" -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonSID -Value "" -Force
    new-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 1 -PropertyType string -Force

    #Disable AppInstall Scheduled Task
    Write-Host "Disabling AppInstall Scheduled Task" -ForegroundColor yellow
    Disable-ScheduledTask -TaskName APPScript

########################################################################################
#######################################  DOMAIN ADD  ###################################
########################################################################################
    #Moved to last step as GPO's locking the desktop during deployment
    $InstCheck = @()
    $InstCheck = (Get-Content $check | Select-String -SimpleMatch "DOMREBOOT")
    if ($InstCheck -eq $null)
    {
    Write-Host "Adding clien to the Domain" -ForegroundColor yellow
    
    #Pre-Create a computer object in AD prior to running this step
    $username = Read-Host "Enter the Domain Intro account name here eg svc_wks_intro"
    $PlainPassword = Read-Host "Enter the Domain Intro account password here eg Password1234"
    $hn = hostname

    #Domain Name and OU path
    $DomainN = "trg.loc"
    $ouPath = "OU=wks,OU=org,DC=trg,DC=Loc"

    #Secure string for password
    $domPassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force

    #Creates username and password credentials
    $credential = New-Object System.Management.Automation.PSCredential ($username,$domPassword)

    Add-Computer -ComputerName $hn -DomainName $DomainN -OUPath $ouPath -Credential $credential -ErrorAction SilentlyContinue

    Write-Host "Rebooting to apply Windows updates" -ForegroundColor yellow
    Add-Content $check -Value "DOMREBOOT" 
    }

    RestartClient

}
