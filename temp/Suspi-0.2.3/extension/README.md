# Suspi

Suspi is the shorten version of Suspicous and designed to analyze indicators with mulpiple providers.

## How to Use

- ip adresses > ipscan
- domains > domainscan
- mails > mailscan
- hashs > hashscan

## Requirements

Add the following tld sites to the trusted domains in order to open them
--> Command Palette --> "Trusted Domains"

```
[
    "https://www.virustotal.com",
    "https://labs.inquest.net",
    "https://otx.alienvault.com",
    "https://urlscan.io",
    "https://www.abuseipdb.com",
    "https://urlhaus.abuse.ch",
    "https://bazaar.abuse.ch",
    "https://crt.sh",
    "https://emailrep.io,
    "https://www.joesecurity.org",
    "https://app.any.run",
    "https://www.filescan.io"
]
```

## Settings

### Providers

You can activate or deactivate Providers.
> Before `Activating` a Provider check if you need an API Key!

### Proxy

You can set a proxy for the requests.

### Exclusions 

Available for:
-  IPs
-  Domains
-  Mails

## Known Issues
- provider quota no implemented
- sometimes notifications are to quick, please check the bell in the right corner

## Disclaimer

This extension is used for quick detection of `known indicators of compromise`, in any case analysis must take place so that errors in the extension can be excluded. 
The Extension is not at the level of a javascript developer, but of an enthusiast.

### TODO
- adding more provider
  - mailhunter
  - greynoise
  - waybackmachine
  - emailrep
  - filescan
  - anyrun
- add sidebar history and logs

## Release Notes

### 0.2.3
- Integrated Proxy request option
  - If you have issues with NTLM Authentication, consider to use [proxyproxy-cli](https://github.com/MarmorY/proxyproxy-cli) a lightweight listener written in Go - Thanks @MarmorY
- Added icon
- small bugfixes

###  0.2.0(1)
- added background worker with Promise
- indicators are now gruped!
- added more provider (not tested)
- changed structure
- added config in settings incl.
  - added exlusions for ip, domain and mail
  - added API keys to specific providers if needed
  - added request timeout value

### 0.1.5

Initial release of Suspi

## Support

**Enjoy!**
If you like buy me a "german" beer