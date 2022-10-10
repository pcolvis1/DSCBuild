Configuration DSCBuild {
    Import-DscResource -ModuleName PsDesiredStateConfiguration
    Import-DscResource -ModuleName AuditPolicyDSC
    Import-DscResource -ModuleName SecurityPolicyDSC 
    #Import-DscResource -ModuleName PSDscResources

    Node @('CIM-APXTEST','CIM-IIS2','CIM-DSCBUILD') {
        #####################################################
        # Ensure SMB Encryption is enabled.
        #####################################################
        Script EnableSMBEncryption {
            # Enable SMB Ecryption on file shares
            GetScript = {
                @{
                    Result = (Get-SmbServerConfiguration | Select-Object EncryptData).EncryptData
                }
            }
            TestScript = {
                (Get-SmbServerConfiguration | Select-Object EncryptData).EncryptData
            }
            SetScript = {
                Set-SmbServerConfiguration -EncryptData 1
            }
        }

        #####################################################
        # Audit Policies for event logging of security events.
        #####################################################
        # Logon/Logoff
        AuditPolicySubcategory LogonSuccess {
            # Ensure logging of successful Logon events
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory LogonFailure {
            # Ensure logging of failed Logon events
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory AccountLockoutSuccess {
            # Ensure logging of Account Lockout events
            Name      = 'Account Lockout'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory SpecialLogonSuccess {
            # Ensure logging of Special Logon events
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory SensitivePrivilegeUseSuccess {
            # Ensure logging of Sensitive Privilege success
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory SensitivePrivilegeUseFailure {
            # Ensure logging of Sensitive Privilege failure
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # File System
        AuditPolicySubcategory FileShareSuccess {
            # Ensure logging of File Share access success
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory FileShareFailure {
            # Ensure logging of File Share access failure
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory FileSystemSuccess {
            # Ensure logging of File System access success
            Name      = 'File System'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory FileSystemFailure {
            # Ensure logging of File System access failure
            Name      = 'File System'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        #####################################################
        # Local Security Policy Enforcement.
        #####################################################
        SecurityOption AuditPolicyEnforce {
            Name      = 'Audit Force Policy'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }

    }
		
	Node @('CIM-APXTEST','CIM-IIS2','CIM-DSCBUILD') {
		#WindowsHardening
        Registry 'EnhancedAntiSpoofing' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueName = 'EnhancedAntiSpoofing'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DCSettingIndex' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'DCSettingIndex'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'ACSettingIndex' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'ACSettingIndex'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DisableInventory' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableInventory'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnableVirtualizationBasedSecurity' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'AllowTelemetry' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'HypervisorEnforcedCodeIntegrity' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'LsaCfgFlags' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'LsaCfgFlags'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'RequirePlatformSecurityFeatures' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueType = 'DWord'
            ValueData = ''
        }
        Registry 'MaxSize' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }
        Registry 'MaxSize1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '196608'
        }
        Registry 'MaxSize2' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }
        Registry 'NoDataExecutionPrevention' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoDataExecutionPrevention'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'NoHeapTerminationOnCorruption' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'NoAutoplayfornonVolume' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'NoGPOListChanges' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoGPOListChanges'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'NoBackgroundPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoBackgroundPolicy'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'EnableUserControl' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AlwaysInstallElevated' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry '\\*\NETLOGON' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\NETLOGON'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
        Registry '\\*\SYSVOL' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\SYSVOL'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
        Registry 'NoLockScreenSlideshow' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'NoLockScreenCamera' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnableScriptBlockInvocationLogging' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'EnableScriptBlockLogging' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnableSmartScreen' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnumerateLocalUsers' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnumerateLocalUsers'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowIndexingEncryptedStoresOrItems' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowUnencryptedTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowBasic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowDigest' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'AllowBasic1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'AllowUnencryptedTraffic1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableBehaviorMonitoring' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableEmailScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueName = 'DisableEmailScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'LocalSettingOverrideSpynetReporting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'LocalSettingOverrideSpynetReporting'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'SpynetReporting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SpynetReporting'
            ValueType = 'DWord'
            ValueData = '2'
        }
        Registry 'DisableAntiSpyware' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender'
            ValueName = 'DisableAntiSpyware'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableHTTPPrinting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableHTTPPrinting'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DisableWebPnPDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'MitigationOptions_FontBocking' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\MitigationOptions'
            ValueName = 'MitigationOptions_FontBocking'
            ValueType = 'String'
            ValueData = '1000000000000'
        }
        Registry 'RestrictRemoteClients' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'RestrictRemoteClients'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'MinEncryptionLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
        }
        Registry 'fDisableCdm' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DisablePasswordSaving' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'fPromptForPassword' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'fEncryptRPCTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnableFirewall' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DefaultInboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DefaultOutboundAction1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'EnableFirewall1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DefaultInboundAction1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'EnableFirewall2' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'DefaultOutboundAction2' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DefaultInboundAction2' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'DWord'
            ValueData = '1'
        }
        Registry 'AdmPwdEnabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'
            ValueName = 'AdmPwdEnabled'
            ValueType = 'DWord'
            ValueData = '1'
		}
		Registry 'PCT1.0Client' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'MPClient' {
			Ensure	  = 'Present'
			Key  	  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'SSL2.0Client' {
			Ensure    = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'SSL3.0Client' {
			Ensure    = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.0Client' {
			Ensure    = 'Present'
			Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.1Client' {
			Ensure	  = 'Present'
			Key 	  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.2Client' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'MPServer' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'PCT1.0Server' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'SSL2.0Server' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'SSL3.0Server' {
			Ensure	  = 'Present'
			Key	      = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.0Server' {
			Ensure	  = 'Present'
			Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.1Server' {
			Ensure	  = 'Present'
			Key	      = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\'
			ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TLS1.2Server' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'CipherNULL' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'DES56/56' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC240/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC256/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC2128/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC440/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC456/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC464/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'RC4128/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '0'
		}
		Registry 'TripleDES168' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'AES128/128' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'AES256/256' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'MD5' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'SHA' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'SHA256' {
			Ensure	  = 'Present'
			Key		  = 'KLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'SHA384' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
		Registry 'SHA512' {
			Ensure	  = 'Present'
			Key		  = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512\'
		   	ValueName = 'Enabled'
			ValueType = 'DWord'
			ValueData = '1'
		}
        WindowsFeature 'Telnet-Client' {
            Name   = 'Telnet-Client'
            Ensure = 'Absent'
        }
        WindowsFeature 'SMB1' {
            Name   = 'FS-SMB1'
            Ensure = 'Absent'
        }
    }
}