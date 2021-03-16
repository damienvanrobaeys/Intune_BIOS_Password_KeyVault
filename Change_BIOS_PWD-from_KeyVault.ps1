$Date = "{0:MMddyy}" -f (Get-Date)
$SystemRoot = $env:SystemRoot
$Debug_Folder = "$SystemRoot\Debug"
$Log_File = "$Debug_Folder\Change_BIOS_Password_$Date.log"

If(!(test-path $Log_File)){new-item $Log_File -type file -force | out-null}

Function Write_Log
	{
		param(
		$Message_Type,	
		$Message
		)
		
		$MyDate = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)		
		Add-Content $Log_File  "$MyDate - $Message_Type : $Message"	
		write-host "$MyDate - $Message_Type : $Message"				
	}

##############################################################################################
# 									Azure app informations
##############################################################################################
# $Script:TenantID = "<Your tenant id>"
# $Script:App_ID = "<Your app ID>"
# $Script:ThumbPrint = "<Your ThumbPrint>"



##############################################################################################
# ********************************************************************************************
# 									 Certificate part
# ********************************************************************************************
##############################################################################################

# If have another method for the certificate you can comment the certificate part
# Just set variable Is_Cert_Installed to $True
# $Is_Cert_Installed = $True

##############################################################################################
# 									Check certificate part
##############################################################################################
# Check if the certificate is installed on the device
$Is_Cert_Installed = $False
$Get_AzureApp_User_Cert = Get-ChildItem -Path Cert:CurrentUser\My | Where{$_.ThumbPrint -eq $ThumbPrint}
$Get_AzureApp_Device_Cert = Get-ChildItem -Path Cert:LocalMachine\My | Where{$_.ThumbPrint -eq $ThumbPrint}
If(($Get_AzureApp_Cert -eq $null) -and ($Get_AzureApp_Device_Cert -eq $null))
	{
		Write_Log -Message_Type "ERROR" -Message "The certificate for Azure authentification is not installed on the device"
	}
Else
	{
		$Is_Cert_Installed = $True	
	}
	

##############################################################################################
# 									Install certificate part
##############################################################################################
# In this part we will download the certificate and import it
If($Is_Cert_Installed -eq $False)
	{
		Write_Log -Message_Type "INFO" -Message "The certificate will be downloading"
	
		# Common part
		$Cert_Name = "MyKeyVault_Cert"
		$Exported_PFX = "$env:TEMP\$Cert_Name.pfx"
		$Cert_Location = "Cert:\LocalMachine\My"
		$PFX_PWD = "intune" | ConvertTo-SecureString -AsPlainText -Force		

		# Choose a method to get the PFX blob storage or Base64, uncomment the appropiare code method

		# Blob storage example
		$PFX_URL = "<Type the path of the PFX on blob storage here>"
		# Invoke-WebRequest -Uri $PFX_URL -OutFile $Exported_PFX                         

		# Base 64 example
		$PFX_B64 = "<Copy the PFX Base64 code there>"
		# [byte[]]$Bytes = [convert]::FromBase64String($PFX_B64)
		# [System.IO.File]::WriteAllBytes($Exported_PFX,$Bytes)

		# Common part
		Try
			{
				Write_Log -Message_Type "INFO" -Message "Importing certificate"			
				Import-PfxCertificate -FilePath $Exported_PFX -CertStoreLocation $Cert_Location -Password $PFX_PWD | out-null
				$Is_Cert_Installed = $True	
				Write_Log -Message_Type "SUCCESS" -Message "Importing certificate"				
			}
		Catch
			{
				Write_Log -Message_Type "ERROR" -Message "Importing certificate"	
				Break
			}
	}
	
##############################################################################################
# ********************************************************************************************
# 									 Certificate part end
# ********************************************************************************************
##############################################################################################	



##############################################################################################
# 									Module install part
##############################################################################################
# In this function we will install: Nuget package provider and modules Az.accounts, Az.KeyVault module
function Get_AzAccount_Module
	{ 
		$Is_Nuget_Installed = $False	
		If(!(Get-PackageProvider | where {$_.Name -eq "Nuget"}))
			{			
				Write_Log -Message_Type "SUCCESS" -Message "The package Nuget is not installed"						
			
				Try
					{
						Write_Log -Message_Type "SUCCESS" -Message "The package Nuget is being installed"						
						[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
						Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force -Confirm:$False | out-null								
						Write_Log -Message_Type "SUCCESS" -Message "The package Nuget has been successfully installed"	
						$Is_Nuget_Installed = $True						
					}
				Catch
					{
						Write_Log -Message_Type "ERROR" -Message "An issue occured while installing package Nuget"	
						Break
					}
			}
		Else
			{
				$Is_Nuget_Installed = $True	
				Write_Log -Message_Type "SUCCESS" -Message "The package Nuget is already installed"										
			}
			
		If($Is_Nuget_Installed -eq $True)
			{
				$Script:Is_Module_Present = $False
				$Modules = @("Az.accounts","Az.KeyVault")
				ForEach($Module_Name in $Modules)
					{
						If (!(Get-InstalledModule $Module_Name)) 
							{ 
								Write_Log -Message_Type "INFO" -Message "The module $Module_Name has not been found"	
								Try
									{
										Write_Log -Message_Type "INFO" -Message "The module $Module_Name is being installed"								
										Install-Module $Module_Name -Force -Confirm:$False -AllowClobber -ErrorAction SilentlyContinue | out-null	
										Write_Log -Message_Type "SUCCESS" -Message "The module $Module_Name has been installed"	
										Write_Log -Message_Type "INFO" -Message "AZ.Accounts version $Module_Version"	
										$Script:Is_Module_Present = $True						
									}
								Catch
									{
										Write_Log -Message_Type "ERROR" -Message "The module $Module_Name has not been installed"			
										write-output "The module $Module_Name has not been installed"						
										EXIT 1							
									}															
							} 
						Else
							{
								Try
									{
										Write_Log -Message_Type "INFO" -Message "The module $Module_Name has been found"												
										Import-Module $Module_Name -Force -ErrorAction SilentlyContinue 
										Write_Log -Message_Type "INFO" -Message "The module $Module_Name has been imported"	
										$Script:Is_Module_Present = $True												
									}
								Catch
									{
										Write_Log -Message_Type "ERROR" -Message "The module $Module_Name has not been imported"	
										write-output "The module $Module_Name has not been imported"						
										EXIT 1							
									}				
							} 				
					}
					
					If ((Get-Module "Az.accounts" -listavailable) -and (Get-Module "Az.KeyVault" -listavailable)) 
						{
							$Script:Is_Module_Present = $True
							Write_Log -Message_Type "INFO" -Message "Both modules are there"																			
						}
			}
	}
		
If($Is_Cert_Installed -eq $True){Get_AzAccount_Module}


##############################################################################################
# 									Main part
##############################################################################################
# In this pat we will connect to the Azure app, get the password from key vault and change BIOS password
If(($Is_Module_Present -eq $True) -and ($Is_Cert_Installed -eq $True))
	{
		If(($TenantID -eq "") -and ($App_ID -eq "") -and ($ThumbPrint -eq ""))
			{
				Write_Log -Message_Type "ERROR" -Message "Info is missing, please fill: TenantID, appid and thumbprint"		
				write-output "Info is missing, please fill: TenantID, appid and thumbprint"						
				EXIT 1					
			}Else
			{
				$Appli_Infos_Filled = $True
			}
			
		If($Appli_Infos_Filled -eq $True)
			{			
				Try
					{
						Write_Log -Message_Type "INFO" -Message "Connecting to your Azure application"														
						Connect-AzAccount -tenantid $TenantID -ApplicationId $App_ID -CertificateThumbprint $ThumbPrint | out-null
						Write_Log -Message_Type "SUCCESS" -Message "Connection OK to your Azure application"			
						$Azure_App_Connnected = $True
					}
				Catch
					{
						Write_Log -Message_Type "ERROR" -Message "Connection KO to your Azure application"	
						write-output "Connection KO to your Azure application"						
						EXIT 1							
					}

				If($Azure_App_Connnected -eq $True)
					{
						# Getting the old password
						$Secret_Old_PWD = (Get-AzKeyVaultSecret -vaultName "SDVault" -name "OldPassword") | select *
						$Get_Old_PWD = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret_Old_PWD.SecretValue) 
						$Old_PWD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Get_Old_PWD) 
						
						# Getting the new password
						$Secret_New_PWD = (Get-AzKeyVaultSecret -vaultName "SDVault" -name "NewPassword") | select *
						$Get_New_PWD = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret_New_PWD.SecretValue) 
						$New_PWD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Get_New_PWD) 						
						
						$Getting_KeyVault_PWD = $True
						
						Write_Log -Message_Type "SUCCESS" -Message "Getting current pasword"	
						Write_Log -Message_Type "SUCCESS" -Message "Getting new pasword"							
					}

				If($Getting_KeyVault_PWD -eq $True)
					{
						$Get_Manufacturer_Info = (gwmi win32_computersystem).Manufacturer
						Write_Log -Message_Type "INFO" -Message "Manufacturer is: $Get_Manufacturer_Info"											

						If(($Get_Manufacturer_Info -notlike "*HP*") -and ($Get_Manufacturer_Info -notlike "*Lenovo*") -and ($Get_Manufacturer_Info -notlike "*Dell*"))
							{
								Write_Log -Message_Type "ERROR" -Message "Device manufacturer not supported"											
								Break
								write-output "Device manufacturer not supported"							
								EXIT 1									
							}

						If($Get_Manufacturer_Info -like "*Lenovo*")
							{
								$IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).PasswordState
							} 
						ElseIf($Get_Manufacturer_Info -like "*HP*")
							{
								$IsPasswordSet = (Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class HP_BIOSSetting | Where-Object Name -eq "Setup password").IsSet
							} 
						ElseIf($Get_Manufacturer_Info -like "*Dell*")
							{
								$module_name = "DellBIOSProvider"
								If (Get-InstalledModule -Name DellBIOSProvider){import-module DellBIOSProvider -Force} 
								Else{Install-Module -Name DellBIOSProvider -Force}	
								$IsPasswordSet = (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).currentvalue 	
							} 							
							
						If(($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq "true") -or ($IsPasswordSet -eq 2))
							{
								$Is_BIOS_Password_Protected = $True	
								Write_Log -Message_Type "INFO" -Message "There is a current BIOS password"																				
							}
						Else
							{
								$Is_BIOS_Password_Protected = $False
								Write_Log -Message_Type "INFO" -Message "There is no current BIOS password"													
							}

						If($Is_BIOS_Password_Protected -eq $True)
							{
								If($Get_Manufacturer_Info -like "*HP*")
									{
										Write_Log -Message_Type "INFO" -Message "Changing BIOS password for HP"											
										Try
										{
											$bios = Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class HP_BIOSSettingInterface
											$bios.SetBIOSSetting("Setup Password","<utf-16/>" + "NewPassword","<utf-16/>" + "OldPassword")				
											Write_Log -Message_Type "SUCCESS" -Message "BIOS password has been changed"	
											write-output "Change password: Success"						
											EXIT 0
										}
										Catch
										{
											Write_Log -Message_Type "ERROR" -Message "BIOS password has not been changed"	
											write-output "Change password: Failed"						
											EXIT 1	
										}		
									} 
								ElseIf($Get_Manufacturer_Info -like "*Lenovo*")
									{																
										Write_Log -Message_Type "INFO" -Message "Changing BIOS password for Lenovo"											
										Try
										{
											$PasswordSet = Get-WmiObject -Namespace root\wmi -Class Lenovo_SetBiosPassword
											$PasswordSet.SetBiosPassword("pap,$Old_PWD,$New_PWD,ascii,us") | out-null			
											Write_Log -Message_Type "SUCCESS" -Message "BIOS password has been changed"	
											write-output "Change password: Success"						
											EXIT 0					
										}
										Catch
										{
											Write_Log -Message_Type "ERROR" -Message "BIOS password has not been changed"		
											write-output "Change password: Failed"						
											EXIT 1						
										}	
									}
								ElseIf($Get_Manufacturer_Info -like "*Dell*")
									{
										Write_Log -Message_Type "INFO" -Message "Changing BIOS password for Dell"	
										$New_PWD_Length = $New_PWD.Length
										If(($New_PWD_Length -lt 4) -or ($New_PWD_Length -gt 32))
											{
												Write_Log -Message_Type "ERROR" -Message "New password length is not correct"	
												Write_Log -Message_Type "ERROR" -Message "Password must contain minimum 4, and maximum 32 characters"			
												Write_Log -Message_Type "INFO" -Message "Password length: $New_PWD_Length"												
												write-output "Password must contain minimum 4, and maximum 32 characters"						
												EXIT 1												
											}
										Else
											{
												Write_Log -Message_Type "INFO" -Message "Password length: $New_PWD_Length"																							
												Try
													{
														Set-Item -Path DellSmbios:\Security\AdminPassword $New_PWD -Password $Old_PWD											
														Write_Log -Message_Type "SUCCESS" -Message "BIOS password has been changed"			
														write-output "Change password: Success"						
														EXIT 0					
													}
													Catch
													{
														Write_Log -Message_Type "ERROR" -Message "BIOS password has not been changed"														
														write-output "Change password: Failed"						
														EXIT 1					
													}												
											}
			
									} 									
							}
						Else
							{
								If($Get_Manufacturer_Info -like "*HP*")
									{
										Write_Log -Message_Type "INFO" -Message "Changing BIOS password for HP"											
										Try
										{
											$bios = Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class HP_BIOSSettingInterface
											$bios.SetBIOSSetting("Setup Password","<utf-16/>" + "NewPassword","<utf-16/>")			
											Write_Log -Message_Type "SUCCESS" -Message "BIOS password has been changed"		
											write-output "Change password: Success"						
											EXIT 0					
										}
										Catch
										{
											Write_Log -Message_Type "ERROR" -Message "BIOS password has not been changed"														
											write-output "Change password: Failed"						
											EXIT 1					
										}				
									} 
								ElseIf($Get_Manufacturer_Info -like "*Lenovo*")
									{
										write-output "The is no current password. An initial password should be configured first"	
										Write_Log -Message_Type "INFO" -Message "There is a current BIOS password"	
										EXIT 1
									} 
								ElseIf($Get_Manufacturer_Info -like "*Dell*")
									{				
										Write_Log -Message_Type "INFO" -Message "Changing BIOS password for Dell"											
										Try
										{
											Set-Item -Path DellSmbios:\Security\AdminPassword "$AdminPwd"
											Write_Log -Message_Type "SUCCESS" -Message "BIOS password has been changed"		
											write-output "Change password: Success"						
											EXIT 0					
										}
										Catch
										{
											Write_Log -Message_Type "ERROR" -Message "BIOS password has not been changed"														
											write-output "Change password: Failed"						
											EXIT 1					
										}					
									} 							
							}
					}					
			}
	}
