# srs2adguard
This is converter from srs sing-box rulesets to AdGuardVPN website exclusion list.

# How it works
The script's input is a text file containing a list of GeoIP and GeoSite rulesets. For example:
```
geoip-cloudflare
geoip-telegram
geosite-anthropic
geosite-openai
```

Conversion is started like this:
```
python srs2adguard.py rulesets.txt -o adguard-proxy.txt
```

The result of the conversion is a text file containing domains and/or IP addresses.

# Dependencies
This script uses third-party tools:
- sing-box
- jq

Convertion tested with `python 3.14.7`, `sing-box 1.14.1` and `jq 1.8.2`.

# Rulesets sources
GeoIP and GeoSite rulesets are loaded from different repositories.

| Ruleset | Repository                               |
| :------ | :--------------------------------------- |
| GeoIP   | https://github.com/Loyalsoldier/geoip    |
| GeoSite | https://github.com/SagerNet/sing-geosite |

# Rulesets processing
## 1. Decompilation
SRS ruleset files are decompiled using `sing-box rule-set decompile` into JSON files.

## 2. Transformation
jq transforms rules from JSON files according to the following rules:
1. If rule type is `domain` or `ip_cidr` it adds value to result list without changes.
2. If rule type is `domain_suffix` it adds `*.` to the beginning of the value and adds it to the result list.

### Example
Some JSON ruleset:
``` json
{
  "version": 1,
  "rules": [
    {
      "domain": "just-domain.com",
      "domain_suffix": "has-subdomains.com"
    }
  ]
}
```

Result website list:
```
*.has-subdomains.com
just-domain.com
```
