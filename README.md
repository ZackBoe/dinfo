# `dinfo` - At a glance domain information

Provides brief information about a provided domain or list of domains, optionally including certificate and whois data.

Allows for pasting entire URLs.

You can include multiple domains or pipe into dinfo via xargs: `cat list.txt | xargs dinfo`  

Will only provide basic information on the first returned IP and first returned nameserver from WHOIS lookup.

Will not display more than 6 cert SANs

Uses IPInfo.io for IP lookup data. Currently does not supply an API key, so may be severely rate limited.


![](https://user-images.githubusercontent.com/904055/84965490-0799c380-b0dd-11ea-9359-54d44d3fc213.png)
