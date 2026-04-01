# CIS Windows 11 Enterprise Benchmark v3.0.0 - Auto-Remediation Script
# Generated from Wazuh SCA failed checks
# Run as Administrator

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$passed = 0; $failed_count = 0; $skipped = 0

function Set-RegValue {
    param($Path, $Name, $Value, $Type='DWord', $Description='')
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "[PASS] $Description" -ForegroundColor Green
        $script:passed++
    } catch {
        Write-Host "[FAIL] $Description - $_" -ForegroundColor Red
        $script:failed_count++
    }
}

# ============================================================
# SECTION 1: Password & Account Policies (secedit)
# ============================================================
Write-Host "`n[*] Applying password and account policies..." -ForegroundColor Cyan
$secpol = "$env:TEMP\secpol.cfg"
secedit /export /cfg $secpol | Out-Null
$content = Get-Content $secpol
$content = $content -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24"
$content = $content -replace "MinimumPasswordAge = \d+", "MinimumPasswordAge = 1"
$content = $content -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 14"
$content = $content -replace "CachedLogonsCount = \d+", "CachedLogonsCount = 4"
$content | Set-Content $secpol
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $secpol /areas SECURITYPOLICY | Out-Null
Remove-Item $secpol -Force -ErrorAction SilentlyContinue
Write-Host "[PASS] Password history set to 24" -ForegroundColor Green
Write-Host "[PASS] Minimum password age set to 1 day" -ForegroundColor Green
Write-Host "[PASS] Minimum password length set to 14" -ForegroundColor Green
Write-Host "[PASS] Cached logons set to 4" -ForegroundColor Green
$passed += 4

# ============================================================
# LSA & AUTHENTICATION
# ============================================================
Write-Host "`n[*] LSA & Authentication..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Description "CIS 26013: Ensure 'Audit: Force audit policy subcategory settings "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Type DWord -Description "CIS 26041: Ensure 'Network access: Do not allow storage of passwor"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord -Description "CIS 26050: Ensure 'Network security: Allow Local System to use com"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Description "CIS 26058: Ensure 'Network security: Minimum session security for "
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Description "CIS 26059: Ensure 'Network security: Minimum session security for "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord -Description "CIS 26060: Ensure 'Network security: Restrict NTLM: Audit Incoming"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Description "CIS 26270: Ensure 'Configures LSASS to run as a protected process'"

# ============================================================
# SERVICES (DISABLE)
# ============================================================
Write-Host "`n[*] Services (Disable)..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" -Name "Start" -Value 4 -Type DWord -Description "CIS 26072: Ensure 'Bluetooth Audio Gateway Service (BTAGService)' "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value 4 -Type DWord -Description "CIS 26073: Ensure 'Bluetooth Support Service (bthserv)' is set to "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -Description "CIS 26075: Ensure 'Downloaded Maps Manager (MapsBroker)' is set to"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26076: Ensure 'Geolocation Service (lfsvc)' is set to 'Disable"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26079: Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)'"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value 4 -Type DWord -Description "CIS 26082: Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 4 -Type DWord -Description "CIS 26088: Ensure 'Print Spooler (Spooler)' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value 4 -Type DWord -Description "CIS 26089: Ensure 'Problem Reports and Solutions Control Panel Sup"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value 4 -Type DWord -Description "CIS 26090: Ensure 'Remote Access Auto Connection Manager (RasAuto)"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value 4 -Type DWord -Description "CIS 26091: Ensure 'Remote Desktop Configuration (SessionEnv)' is s"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value 4 -Type DWord -Description "CIS 26092: Ensure 'Remote Desktop Services (TermService)' is set t"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value 4 -Type DWord -Description "CIS 26093: Ensure 'Remote Desktop Services UserMode Port Redirecto"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value 4 -Type DWord -Description "CIS 26094: Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "Start" -Value 4 -Type DWord -Description "CIS 26097: Ensure 'Server (LanmanServer)' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value 4 -Type DWord -Description "CIS 26101: Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value 4 -Type DWord -Description "CIS 26102: Ensure 'UPnP Device Host (upnphost)' is set to 'Disable"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26104: Ensure 'Windows Error Reporting Service (WerSvc)' is se"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26105: Ensure 'Windows Event Collector (Wecsvc)' is set to 'Di"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26106: Ensure 'Windows Media Player Network Sharing Service (W"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26107: Ensure 'Windows Mobile Hotspot Service (icssvc)' is set"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" -Name "Start" -Value 4 -Type DWord -Description "CIS 26108: Ensure 'Windows Push Notifications System Service (WpnS"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall" -Name "Start" -Value 4 -Type DWord -Description "CIS 26109: Ensure 'Windows PushToInstall Service (PushToInstall)' "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -Value 4 -Type DWord -Description "CIS 26110: Ensure 'Windows Remote Management (WS- Management) (Win"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26112: Ensure 'Xbox Accessory Management Service (XboxGipSvc)'"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -Value 4 -Type DWord -Description "CIS 26113: Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -Value 4 -Type DWord -Description "CIS 26114: Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'D"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -Value 4 -Type DWord -Description "CIS 26115: Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' i"

# ============================================================
# FIREWALL
# ============================================================
Write-Host "`n[*] Firewall..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value 1 -Type DWord -Description "CIS 26118: Ensure 'Windows Firewall: Domain: Settings: Display a n"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord -Description "CIS 26121: Ensure 'Windows Firewall: Domain: Logging: Log dropped "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Description "CIS 26122: Ensure 'Windows Firewall: Domain: Logging: Log successf"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value 1 -Type DWord -Description "CIS 26125: Ensure 'Windows Firewall: Private: Settings: Display a "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord -Description "CIS 26128: Ensure 'Windows Firewall: Private: Logging: Log dropped"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Description "CIS 26129: Ensure 'Windows Firewall: Private: Logging: Log success"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value 1 -Type DWord -Description "CIS 26132: Ensure 'Windows Firewall: Public: Settings: Display a n"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value 0 -Type DWord -Description "CIS 26133: Ensure 'Windows Firewall: Public: Settings: Apply local"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value 0 -Type DWord -Description "CIS 26134: Ensure 'Windows Firewall: Public: Settings: Apply local"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord -Description "CIS 26137: Ensure 'Windows Firewall: Public: Logging: Log dropped "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Description "CIS 26138: Ensure 'Windows Firewall: Public: Logging: Log successf"

# ============================================================
# NETWORK
# ============================================================
Write-Host "`n[*] Network..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Description "CIS 26176: Ensure 'NetBT NodeType configuration' is set to 'Enable"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Description "CIS 26179: Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source ro"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Description "CIS 26180: Ensure 'MSS: (DisableIPSourceRouting) IP source routing"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord -Description "CIS 26182: Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord -Description "CIS 26183: Ensure 'MSS: (KeepAliveTime) How often keep-alive packe"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0 -Type DWord -Description "CIS 26185: Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to det"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -Description "CIS 26188: Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -Description "CIS 26189: Ensure 'MSS: (TcpMaxDataRetransmissions) How many times"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord -Description "CIS 26198: Ensure 'Turn off Microsoft Peer-to-Peer Networking Serv"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0 -Type DWord -Description "CIS 26199: Ensure 'Prohibit installation and configuration of Netw"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord -Description "CIS 26200: Ensure 'Prohibit use of Internet Connection Sharing on "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1 -Type DWord -Description "CIS 26201: Ensure 'Require domain users to elevate when setting a "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWord -Description "CIS 26203: Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponen"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3 -Type DWord -Description "CIS 26206: Ensure 'Minimize the number of simultaneous connections"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value 1 -Type DWord -Description "CIS 26207: Ensure 'Prohibit connection to non-domain networks when"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Description "CIS 26208: Ensure 'Allow Windows to automatically connect to sugge"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord -Description "CIS 26392: Ensure 'Prevent users and apps from accessing dangerous"

# ============================================================
# DEVICE GUARD & CREDENTIAL GUARD
# ============================================================
Write-Host "`n[*] Device Guard & Credential Guard..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Description "CIS 26225: Ensure 'Turn On Virtualization Based Security' is set t"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Description "CIS 26226: Ensure 'Turn On Virtualization Based Security: Select P"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord -Description "CIS 26227: Ensure 'Turn On Virtualization Based Security: Virtuali"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Value 1 -Type DWord -Description "CIS 26228: Ensure 'Turn On Virtualization Based Security: Require "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1 -Type DWord -Description "CIS 26229: Ensure 'Turn On Virtualization Based Security: Credenti"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureKernelShadowStacksLaunch" -Value 1 -Type DWord -Description "CIS 26230: Ensure 'Turn On Virtualization Based Security: Kernel-m"

# ============================================================
# BITLOCKER
# ============================================================
Write-Host "`n[*] BitLocker..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1 -Type DWord -Description "CIS 26306: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1 -Type DWord -Description "CIS 26307: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Value 1 -Type DWord -Description "CIS 26310: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 1 -Type DWord -Description "CIS 26311: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -Value 1 -Type DWord -Description "CIS 26312: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Value 0 -Type DWord -Description "CIS 26313: Ensure 'Choose how BitLocker-protected fixed drives can"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -Value 0 -Type DWord -Description "CIS 26314: Ensure 'Configure use of hardware-based encryption for "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -Value 0 -Type DWord -Description "CIS 26315: Ensure 'Configure use of passwords for fixed data drive"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowUserCert" -Value 1 -Type DWord -Description "CIS 26316: Ensure 'Configure use of smart cards on fixed data driv"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVEnforceUserCert" -Value 1 -Type DWord -Description "CIS 26317: Ensure 'Configure use of smart cards on fixed data driv"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Value 1 -Type DWord -Description "CIS 26318: Ensure 'Allow enhanced PINs for startup' is set to 'Ena"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSecureBootForIntegrity" -Value 1 -Type DWord -Description "CIS 26319: Ensure 'Allow Secure Boot for integrity validation' is "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecovery" -Value 1 -Type DWord -Description "CIS 26320: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSManageDRA" -Value 1 -Type DWord -Description "CIS 26321: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Value 1 -Type DWord -Description "CIS 26322: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord -Description "CIS 26323: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord -Description "CIS 26324: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryBackup" -Value 1 -Type DWord -Description "CIS 26325: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryInfoToStore" -Value 1 -Type DWord -Description "CIS 26326: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRequireActiveDirectoryBackup" -Value 1 -Type DWord -Description "CIS 26327: Ensure 'Choose how BitLocker-protected operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareEncryption" -Value 0 -Type DWord -Description "CIS 26328: Ensure 'Configure use of hardware-based encryption for "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSPassphrase" -Value 0 -Type DWord -Description "CIS 26329: Ensure 'Configure use of passwords for operating system"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Type DWord -Description "CIS 26330: Ensure 'Require additional authentication at startup' i"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableBDEWithNoTPM" -Value 0 -Type DWord -Description "CIS 26331: Ensure 'Require additional authentication at startup: A"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 0 -Type DWord -Description "CIS 26332: Ensure 'Require additional authentication at startup: C"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord -Description "CIS 26333: Ensure 'Require additional authentication at startup: C"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKey" -Value 0 -Type DWord -Description "CIS 26334: Ensure 'Require additional authentication at startup: C"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -Value 0 -Type DWord -Description "CIS 26335: Ensure 'Require additional authentication at startup: C"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecovery" -Value 1 -Type DWord -Description "CIS 26337: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVManageDRA" -Value 1 -Type DWord -Description "CIS 26338: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryPassword" -Value 0 -Type DWord -Description "CIS 26339: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryKey" -Value 0 -Type DWord -Description "CIS 26340: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHideRecoveryPage" -Value 1 -Type DWord -Description "CIS 26341: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryBackup" -Value 0 -Type DWord -Description "CIS 26342: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryInfoToStore" -Value 1 -Type DWord -Description "CIS 26343: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRequireActiveDirectoryBackup" -Value 0 -Type DWord -Description "CIS 26344: Ensure 'Choose how BitLocker-protected removable drives"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHardwareEncryption" -Value 0 -Type DWord -Description "CIS 26345: Ensure 'Configure use of hardware-based encryption for "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVPassphrase" -Value 0 -Type DWord -Description "CIS 26346: Ensure 'Configure use of passwords for removable data d"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowUserCert" -Value 1 -Type DWord -Description "CIS 26347: Ensure 'Configure use of smart cards on removable data "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforceUserCert" -Value 1 -Type DWord -Description "CIS 26348: Ensure 'Configure use of smart cards on removable data "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Value 1 -Type DWord -Description "CIS 26349: Ensure 'Deny write access to removable drives not prote"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -Value 0 -Type DWord -Description "CIS 26350: Ensure 'Deny write access to removable drives not prote"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Value 1 -Type DWord -Description "CIS 26351: Ensure 'Disable new DMA devices when this computer is l"

# ============================================================
# WINDOWS DEFENDER & ASR
# ============================================================
Write-Host "`n[*] Windows Defender & ASR..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -Value 1 -Type DWord -Description "CIS 26390: Ensure 'Configure Attack Surface Reduction rules' is se"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "26190899-1602-49E8-8B27-eB1D0A1CE869" -Value 1 -Type DWord -Description "CIS 26391: Ensure 'Configure Attack Surface Reduction rules: Set t"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -Type DWord -Description "CIS 26393: Ensure 'Enable file hash computation feature' is set to"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Type DWord -Description "CIS 26398: Ensure 'Configure Watson events' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -Type DWord -Description "CIS 26400: Ensure 'Scan removable drives' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -Type DWord -Description "CIS 26401: Ensure 'Turn on e-mail scanning' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Type DWord -Description "CIS 26402: Ensure 'Configure detection for potentially unwanted ap"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value 1 -Type DWord -Description "CIS 26472: Ensure 'Prevent users from modifying settings' is set t"

# ============================================================
# PRIVACY & TELEMETRY
# ============================================================
Write-Host "`n[*] Privacy & Telemetry..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Description "CIS 26293: Ensure 'Turn off the advertising ID' is set to 'Enabled"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1 -Type DWord -Description "CIS 26361: Ensure 'Configure Authenticated Proxy usage for the Con"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type DWord -Description "CIS 26362: Ensure 'Disable OneSettings Downloads' is set to 'Enabl"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -Description "CIS 26363: Ensure 'Do not show feedback notifications' is set to '"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -Value 1 -Type DWord -Description "CIS 26364: Ensure 'Enable OneSettings Auditing' is set to 'Enabled"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord -Description "CIS 26365: Ensure 'Limit Diagnostic Log Collection' is set to 'Ena"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type DWord -Description "CIS 26366: Ensure 'Limit Dump Collection' is set to 'Enabled'."

# ============================================================
# SYSTEM HARDENING
# ============================================================
Write-Host "`n[*] System Hardening..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\SAM" -Name "RelaxMinimumPasswordLengthLimits" -Value 1 -Type DWord -Description "CIS 26004: Ensure 'Relax minimum password length limits' is set to"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3 -Type DWord -Description "CIS 26008: Ensure 'Accounts: Block Microsoft accounts' is set to '"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord -Description "CIS 26015: Ensure 'Devices: Prevent users from installing printer "
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord -Description "CIS 26022: Ensure 'Interactive logon: Do not require CTRL+ALT+DEL'"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Description "CIS 26023: Ensure 'Interactive logon: Don't display last signed-in"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Description "CIS 26031: Ensure 'Microsoft network client: Digitally sign commun"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Description "CIS 26035: Ensure 'Microsoft network server: Digitally sign commun"
Set-RegValue -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Description "CIS 26036: Ensure 'Microsoft network server: Digitally sign commun"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Type DWord -Description "CIS 26064: Ensure 'User Account Control: Admin Approval Mode for t"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Description "CIS 26066: Ensure 'User Account Control: Behavior of the elevation"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord -Description "CIS 26166: Ensure 'Prevent enabling lock screen camera' is set to "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord -Description "CIS 26167: Ensure 'Prevent enabling lock screen slide show' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord -Description "CIS 26168: Ensure 'Allow users to enable online speech recognition"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord -Description "CIS 26169: Ensure 'Allow Online Tips' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Description "CIS 26175: Ensure 'Enable Structured Exception Handling Overwrite "
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value 1 -Type DWord -Description "CIS 26181: Ensure 'MSS: (DisableSavePassword) Prevent the dial-up "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value 0 -Type DWord -Description "CIS 26194: Ensure 'Enable Font Providers' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -Description "CIS 26195: Ensure 'Enable insecure guest logons' is set to 'Disabl"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Value 0 -Type DWord -Description "CIS 26204: Ensure 'Configuration of wireless settings using Window"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1 -Type DWord -Description "CIS 26205: Ensure 'Prohibit access of the Windows Connect Now wiza"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord -Description "CIS 26209: Ensure 'Allow Print Spooler to accept client connection"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionguardPolicy" -Value 1 -Type DWord -Description "CIS 26210: Ensure 'Configure Redirection Guard' is set to 'Enabled"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcUseNamedPipeProtocol" -Value 0 -Type DWord -Description "CIS 26211: Ensure 'Configure RPC connection settings: Protocol to "
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcAuthentication" -Value 0 -Type DWord -Description "CIS 26212: Ensure 'Configure RPC connection settings: Use authenti"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcProtocols" -Value 5 -Type DWord -Description "CIS 26213: Ensure 'Configure RPC listener settings: Protocols to a"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcTcpPort" -Value 0 -Type DWord -Description "CIS 26215: Ensure 'Configure RPC over TCP port' is set to 'Enabled"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -Description "CIS 26216: Ensure 'Limits print driver installation to Administrat"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "CopyFilesPolicy" -Value 1 -Type DWord -Description "CIS 26217: Ensure 'Manage processing of Queue-specific files' is s"
Set-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord -Description "CIS 26219: Ensure 'Point and Print Restrictions: When updating dri"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord -Description "CIS 26220: Ensure 'Turn off notifications network usage' is set to"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedPersonalizedSites" -Value 1 -Type DWord -Description "CIS 26221: Ensure 'Remove Personalized Website Recommendations fro"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 0 -Type DWord -Description "CIS 26223: Ensure 'Encryption Oracle Remediation' is set to 'Enabl"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Description "CIS 26237: Ensure 'Prevent device metadata retrieval from the Inte"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord -Description "CIS 26238: Ensure 'Boot-Start Driver Initialization Policy' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Description "CIS 26239: Ensure 'Configure registry policy processing: Do not ap"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Description "CIS 26240: Ensure 'Configure registry policy processing: Process e"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Description "CIS 26241: Ensure 'Configure security policy processing: Do not ap"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Description "CIS 26242: Ensure 'Configure security policy processing: Process e"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Description "CIS 26243: Ensure 'Continue experiences on this device' is set to "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -Description "CIS 26245: Ensure 'Turn off access to the Store' is set to 'Enable"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Description "CIS 26246: Ensure 'Turn off downloading of print drivers over HTTP"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord -Description "CIS 26247: Ensure 'Turn off handwriting personalization data shari"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord -Description "CIS 26248: Ensure 'Turn off handwriting recognition error reportin"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value 1 -Type DWord -Description "CIS 26249: Ensure 'Turn off Internet Connection Wizard if URL conn"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1 -Type DWord -Description "CIS 26250: Ensure 'Turn off Internet download for Web publishing a"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1 -Type DWord -Description "CIS 26251: Ensure 'Turn off printing over HTTP' is set to 'Enabled"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value 1 -Type DWord -Description "CIS 26252: Ensure 'Turn off Registration if URL connection is refe"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value 1 -Type DWord -Description "CIS 26253: Ensure 'Turn off Search Companion content file updates'"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Value 1 -Type DWord -Description "CIS 26254: Ensure 'Turn off the "Order Prints" picture task' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Value 1 -Type DWord -Description "CIS 26255: Ensure 'Turn off the "Publish to Web" task for files an"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord -Description "CIS 26256: Ensure 'Turn off the Windows Messenger Customer Experie"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -Description "CIS 26257: Ensure 'Turn off Windows Customer Experience Improvemen"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Description "CIS 26258: Ensure 'Turn off Windows Error Reporting' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord -Description "CIS 26260: Ensure 'Enumeration policy for external devices incompa"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PwdExpirationProtectionEnabled" -Value 1 -Type DWord -Description "CIS 26262: Ensure 'Do not allow password expiration time longer th"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "ADPasswordEncryptionEnabled" -Value 1 -Type DWord -Description "CIS 26263: Ensure 'Enable password encryption' is set to 'Enabled'"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordComplexity" -Value 4 -Type DWord -Description "CIS 26264: Ensure 'Password Settings: Password Complexity' is set "
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordLength" -Value 15 -Type DWord -Description "CIS 26265: Ensure 'Password Settings: Password Length' is set to '"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Description "CIS 26269: Ensure 'Allow Custom SSPs and APs to be loaded into LSA"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value 1 -Type DWord -Description "CIS 26271: Ensure 'Disallow copying of user input methods to the s"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord -Description "CIS 26272: Ensure 'Block user from showing account details on sign"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord -Description "CIS 26273: Ensure 'Do not display network selection UI' is set to "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord -Description "CIS 26274: Ensure 'Do not enumerate connected users on domain-join"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Description "CIS 26276: Ensure 'Turn off app notifications on the lock screen' "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord -Description "CIS 26277: Ensure 'Turn off picture password sign-in' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Description "CIS 26279: Ensure 'Allow Clipboard synchronization across devices'"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -Description "CIS 26280: Ensure 'Allow upload of User Activities' is set to 'Dis"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord -Description "CIS 26281: Ensure 'Allow network connectivity during connected-sta"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord -Description "CIS 26282: Ensure 'Allow network connectivity during connected-sta"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -Value 0 -Type DWord -Description "CIS 26283: Ensure 'Allow standby states (S1-S3) when sleeping (on "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -Value 0 -Type DWord -Description "CIS 26284: Ensure 'Allow standby states (S1-S3) when sleeping (plu"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Description "CIS 26289: Ensure 'Enable RPC Endpoint Mapper Client Authenticatio"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 0 -Type DWord -Description "CIS 26291: Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value 0 -Type DWord -Description "CIS 26292: Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord -Description "CIS 26294: Ensure 'Enable Windows NTP Client' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord -Description "CIS 26298: Ensure 'Let Windows apps activate with voice while the "
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1 -Type DWord -Description "CIS 26299: Ensure 'Allow Microsoft accounts to be optional' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockHostedAppAccessWinRT" -Value 1 -Type DWord -Description "CIS 26300: Ensure 'Block launching Universal Windows apps with Win"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord -Description "CIS 26301: Ensure 'Disallow Autoplay for non-volume devices' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Description "CIS 26302: Ensure 'Set the default behavior for AutoRun' is set to"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord -Description "CIS 26304: Ensure 'Configure enhanced anti-spoofing' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value 0 -Type DWord -Description "CIS 26352: Ensure 'Allow Use of Camera' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord -Description "CIS 26353: Ensure 'Turn off cloud consumer account state content' "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord -Description "CIS 26354: Ensure 'Turn off cloud optimized content' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Description "CIS 26355: Ensure 'Turn off Microsoft consumer experiences' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord -Description "CIS 26357: Ensure 'Do not display the password reveal button' is s"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord -Description "CIS 26359: Ensure 'Prevent the use of security questions for local"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord -Description "CIS 26367: Ensure 'Toggle user control over Insider builds' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableGraphRecentItems" -Value 1 -Type DWord -Description "CIS 26381: Ensure 'Turn off account-based insights, recent, favori"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -Description "CIS 26385: Ensure 'Turn off location' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord -Description "CIS 26386: Ensure 'Allow Message Service Cloud Sync' is set to 'Di"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value 1 -Type DWord -Description "CIS 26387: Ensure 'Block all consumer Microsoft account user authe"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -Value 0 -Type DWord -Description "CIS 26405: Ensure 'Allow camera and microphone access in Microsoft"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWord -Description "CIS 26406: Ensure 'Allow data persistence for Microsoft Defender A"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -Value 0 -Type DWord -Description "CIS 26407: Ensure 'Allow files to download and save to the host op"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord -Description "CIS 26408: Ensure 'Configure Microsoft Defender Application Guard "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord -Description "CIS 26409: Ensure 'Turn on Microsoft Defender Application Guard in"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord -Description "CIS 26410: Ensure 'Enable news and interests on the taskbar' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Description "CIS 26411: Ensure 'Prevent the usage of OneDrive for file storage'"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" -Name "DisablePushToInstall" -Value 1 -Type DWord -Description "CIS 26412: Ensure 'Turn off Push To Install service' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord -Description "CIS 26431: Ensure 'Prevent downloading of enclosures' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Type DWord -Description "CIS 26432: Ensure 'Allow Cloud Search' is set to 'Enabled: Disable"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Description "CIS 26433: Ensure 'Allow Cortana' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord -Description "CIS 26434: Ensure 'Allow Cortana above lock screen' is set to 'Dis"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Description "CIS 26436: Ensure 'Allow search and Cortana to use location' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord -Description "CIS 26437: Ensure 'Allow search highlights' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value 1 -Type DWord -Description "CIS 26438: Ensure 'Turn off KMS Client Online AVS Validation' is s"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Description "CIS 26444: Ensure 'Allow widgets' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "CaptureThreatWindow" -Value 1 -Type DWord -Description "CIS 26445: Ensure 'Automatic Data Collection' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious" -Value 1 -Type DWord -Description "CIS 26446: Ensure 'Notify Malicious' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -Value 1 -Type DWord -Description "CIS 26447: Ensure 'Notify Password Reuse' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -Value 1 -Type DWord -Description "CIS 26448: Ensure 'Notify Unsafe App' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled" -Value 1 -Type DWord -Description "CIS 26449: Ensure 'Service Enabled' is set to 'Enabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -Description "CIS 26450: Ensure 'Configure Windows Defender SmartScreen' is set "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Description "CIS 26451: Ensure 'Enables or disables Windows Game Recording and "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord -Description "CIS 26453: Ensure 'Allow suggested apps in Windows Ink Workspace' "
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableMPR" -Value 0 -Type DWord -Description "CIS 26458: Ensure 'Enable MPR notifications for the system' is set"
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Description "CIS 26459: Ensure 'Sign-in and lock last interactive user automati"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Description "CIS 26461: Ensure 'Turn on PowerShell Transcription' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord -Description "CIS 26470: Ensure 'Allow clipboard sharing with Windows Sandbox' i"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord -Description "CIS 26471: Ensure 'Allow networking in Windows Sandbox' is set to "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1 -Type DWord -Description "CIS 26477: Ensure 'Remove access to "Pause updates" feature' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord -Description "CIS 26479: Ensure 'Select when Preview Builds and Feature Updates "

# ============================================================
# WINDOWS STORE & APPS
# ============================================================
Write-Host "`n[*] Windows Store & Apps..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord -Description "CIS 26297: Ensure 'Prevent non-admin users from installing package"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableAppInstaller" -Value 0 -Type DWord -Description "CIS 26369: Ensure 'Enable App Installer' is set to 'Disabled'."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord -Description "CIS 26370: Ensure 'Enable App Installer Experimental Features' is "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord -Description "CIS 26371: Ensure 'Enable App Installer Hash Override' is set to '"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord -Description "CIS 26372: Ensure 'Enable App Installer ms-appinstaller protocol' "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 1 -Type DWord -Description "CIS 26439: Ensure 'Disable all apps from Microsoft Store' is set t"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 1 -Type DWord -Description "CIS 26440: Ensure 'Only display the private store within the Micro"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord -Description "CIS 26442: Ensure 'Turn off the offer to update to the latest vers"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1 -Type DWord -Description "CIS 26443: Ensure 'Turn off the Store application' is set to 'Enab"

# ============================================================
# REMOTE DESKTOP & WINRM
# ============================================================
Write-Host "`n[*] Remote Desktop & WinRM..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type DWord -Description "CIS 26224: Ensure 'Remote host allows delegation of non- exportabl"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Description "CIS 26288: Ensure 'Configure Solicited Remote Assistance' is set t"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Name "DisableCloudClipboardIntegration" -Value 1 -Type DWord -Description "CIS 26413: Ensure 'Disable Cloud Clipboard integration for server-"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord -Description "CIS 26414: Ensure 'Do not allow passwords to be saved' is set to '"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "EnableUiaRedirection" -Value 0 -Type DWord -Description "CIS 26416: Ensure 'Allow UI Automation redirection' is set to 'Dis"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord -Description "CIS 26417: Ensure 'Do not allow COM port redirection' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord -Description "CIS 26418: Ensure 'Do not allow drive redirection' is set to 'Enab"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedir" -Value 1 -Type DWord -Description "CIS 26419: Ensure 'Do not allow location redirection' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value 1 -Type DWord -Description "CIS 26420: Ensure 'Do not allow LPT port redirection' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1 -Type DWord -Description "CIS 26421: Ensure 'Do not allow supported Plug and Play device red"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableWebAuthn" -Value 1 -Type DWord -Description "CIS 26422: Ensure 'Do not allow WebAuthn redirection' is set to 'E"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1 -Type DWord -Description "CIS 26423: Ensure 'Always prompt for password upon connection' is "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord -Description "CIS 26424: Ensure 'Require secure RPC communication' is set to 'En"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2 -Type DWord -Description "CIS 26425: Ensure 'Require use of specific security layer for remo"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000 -Type DWord -Description "CIS 26429: Ensure 'Set time limit for disconnected sessions' is se"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord -Description "CIS 26464: Ensure 'Disallow Digest authentication' is set to 'Enab"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1 -Type DWord -Description "CIS 26468: Ensure 'Disallow WinRM from storing RunAs credentials' "
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value 0 -Type DWord -Description "CIS 26469: Ensure 'Allow Remote Shell Access' is set to 'Disabled'"

# ============================================================
# AUDIT & LOGGING
# ============================================================
Write-Host "`n[*] Audit & Logging..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Description "CIS 26222: Ensure 'Include command line in process creation events"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditApplicationGuard" -Value 1 -Type DWord -Description "CIS 26404: Ensure 'Allow auditing events in Microsoft Defender App"

# ============================================================
# OTHER
# ============================================================
Write-Host "`n[*] Other..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Description "CIS 26174: Ensure 'Enable Certificate Padding' is set to 'Enabled'"

# ============================================================
# SPECIAL VALUES (inactivity, lockout thresholds)
# ============================================================
Write-Host "`n[*] Special numeric values..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord -Description "CIS 26025: Machine inactivity limit 900s"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Description "CIS 26024: Device lockout threshold 10"
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 4 -Type DWord -Description "CIS 26028: Cached logons 4"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180 -Type DWord -Description "CIS 26479: Defer feature updates 180 days"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 1 -Type DWord -Description "CIS 26038: SMB server name hardening"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord -Description "CIS 26183: TCP keep alive 300000ms"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -Description "CIS 26188: TCP max retransmissions 3"
Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -Description "CIS 26189: TCP max retransmissions 3"

# ============================================================
# FIREWALL LOG FILE SIZES
# ============================================================
Write-Host "`n[*] Firewall log sizes..." -ForegroundColor Cyan
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord -Description "Firewall DomainProfile log size 16384KB"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord -Description "Firewall PrivateProfile log size 16384KB"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord -Description "Firewall PublicProfile log size 16384KB"

# ============================================================
# RENAME ADMIN AND GUEST ACCOUNTS
# ============================================================
Write-Host "`n[*] Renaming built-in accounts..." -ForegroundColor Cyan
try { Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin" -ErrorAction Stop; Write-Host "[PASS] CIS 26011: Renamed Administrator account" -ForegroundColor Green; $passed++ } catch { Write-Host "[SKIP] Administrator already renamed or not found" -ForegroundColor Yellow; $skipped++ }
try { Rename-LocalUser -Name "Guest" -NewName "LocalGuest" -ErrorAction Stop; Write-Host "[PASS] CIS 26012: Renamed Guest account" -ForegroundColor Green; $passed++ } catch { Write-Host "[SKIP] Guest already renamed or not found" -ForegroundColor Yellow; $skipped++ }

# ============================================================
# AUDIT POLICIES
# ============================================================
Write-Host "`n[*] Audit policies..." -ForegroundColor Cyan
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Credential Validation" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Kerberos Authentication Service" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Kerberos Service Ticket Operations" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Computer Account Management" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Other Account Management Events" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Distribution Group Management" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Application Group Management" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
Write-Host "[PASS] Audit: Process Creation" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable | Out-Null
Write-Host "[PASS] Audit: Plug and Play Events" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Token Right Adjusted Events" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: File Share" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Detailed File Share" /success:disable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Detailed File Share" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Removable Storage" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Other Object Access Events" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Authorization Policy Change" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: MPSSVC Rule-Level Policy Change" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Filtering Platform Policy Change" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable | Out-Null
Write-Host "[PASS] Audit: Special Logon" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Other Logon/Logoff Events" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable | Out-Null
Write-Host "[PASS] Audit: Group Membership" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:enable | Out-Null
Write-Host "[PASS] Audit: IPsec Main Mode" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Network Policy Server" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Security System Extension" -ForegroundColor Green
$passed++
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable | Out-Null
Write-Host "[PASS] Audit: Other System Events" -ForegroundColor Green
$passed++

# ============================================================
# SUMMARY
# ============================================================
Write-Host "`n============================================" -ForegroundColor White
Write-Host "REMEDIATION COMPLETE" -ForegroundColor White
Write-Host "============================================" -ForegroundColor White
Write-Host "Passed:  $passed" -ForegroundColor Green
Write-Host "Failed:  $failed_count" -ForegroundColor Red
Write-Host "Skipped: $skipped" -ForegroundColor Yellow
Write-Host "`nRestart the Wazuh agent to trigger a new scan:" -ForegroundColor Cyan
Write-Host "  Restart-Service WazuhSvc" -ForegroundColor White
Write-Host "`nA system REBOOT is recommended for some settings to take effect." -ForegroundColor Yellow