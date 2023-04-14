# Suspi

suspi is the shorten version of `Suspicous` and helps to quickly show indicators of compromise with mulpiple providers.

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
- mailscan not functional yet
- some providers are not fully implemented
- provider quota no implemented
- sometimes notifications are to quick, please check the bell in the right corner

## Disclaimer

This extension is in early stage and only used for quick detection of `known indicators of compromise`.<br>
It doesn't it does not replace a proper analysis.<br>

### TODO
- adding more provider
  - mailhunter
  - greynoise
  - waybackmachine
  - emailrep
  - filescan
  - anyrun
- add sidebar history and logs
- may change to class system

## Release Notes

### 0.2.4

- added repository support for extension
- small improvments

### 0.2.3
- integrated Proxy request in settings
  - if you have issues with NTLM Authentication, consider to use [proxyproxy-cli](https://github.com/MarmorY/proxyproxy-cli) a lightweight listener written in Go - Thanks @MarmorY
- added icon
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

initial release of suspi

## Support

**Enjoy!**
if you like leave a star or write a message to suspi[at]th1s1s[.]de