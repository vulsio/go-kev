# go-kev
`go-kev` build a local copy of Known Exploited Vulnerabilities Catalog by CISA.

# Usage
```console
$ go-kev help
Go Known Exploited Vulnerabilities

Usage:
  go-kev [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  fetch       Fetch the data of vulnerabilities
  help        Help about any command
  server      Start go-kev HTTP server
  version     Show version

Flags:
      --config string       config file (default is $HOME/.go-kev.yaml)
      --dbpath string       /path/to/sqlite3 or SQL connection string
      --dbtype string       Database type to store data in (sqlite3, mysql, postgres or redis supported)
      --debug               debug mode (default: false)
      --debug-sql           SQL debug mode
  -h, --help                help for go-kev
      --http-proxy string   http://proxy-url:port (default: empty)
      --log-dir string      /path/to/log
      --log-json            output log as JSON
      --log-to-file         output log to file
      --quiet               quiet mode (no output)

Use "go-kev [command] --help" for more information about a command.
```

# Fetch CISA Known Exploited Vulnerabilities
```console
$ go-kev fetch kevuln
INFO[11-16|04:39:00] Fetching Known Exploited Vulnerabilities 
INFO[11-16|04:39:00] Fetching                                 URL=https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
INFO[11-16|04:39:00] Insert Known Exploited Vulnerabilities into go-kev. db=sqlite3
INFO[11-16|04:39:00] Inserting Known Exploited Vulnerabilities... 
291 / 291 [------------------------------------------------------------------------------] 100.00% ? p/s
INFO[11-16|04:39:00] CveID Count                              count=291
```

# Fetch VulnCheck Known Exploited Vulnerabilities (https://vulncheck.com/kev)
Before you use this data from VulnCheck, you MUST read https://docs.vulncheck.com/community/vulncheck-kev/attribution and make sure it's satisfied.

```console
$ go-kev fetch vulncheck
INFO[08-23|02:34:55] Fetching VulnCheck Known Exploited Vulnerabilities 
INFO[08-23|02:34:56] Insert VulnCheck Known Exploited Vulnerabilities into go-kev. db=sqlite3
INFO[08-23|02:34:56] Inserting VulnCheck Known Exploited Vulnerabilities... 
2832 / 2832 [------------------------------------------------------------------------------] 100.00% 2931 p/s
INFO[08-23|02:34:57] CveID Count                              count=2832
```

# Server mode
```console
$ go-kev server 
INFO[11-16|04:40:28] Starting HTTP Server... 
INFO[11-16|04:40:28] Listening...                             URL=127.0.0.1:1328

   ____    __
  / __/___/ /  ___
 / _// __/ _ \/ _ \
/___/\__/_//_/\___/ v3.3.10-dev
High performance, minimalist Go web framework
https://echo.labstack.com
____________________________________O/_______
                                    O\
⇨ http server started on 127.0.0.1:1328
{"time":"2021-11-16T04:40:30.511368993+09:00","id":"","remote_ip":"127.0.0.1","host":"127.0.0.1:1328","method":"GET","uri":"/cves/CVE-2021-27104​","user_agent":"curl/7.68.0","status":200,"error":"","latency":5870905,"latency_human":"5.870905ms","bytes_in":0,"bytes_out":397}

$ curl http://127.0.0.1:1328/cves/CVE-2021-27104 | jq
{
  "cisa": [
    {
      "cveID": "CVE-2021-27104",
      "vendorProject": "Accellion",
      "product": "FTA",
      "vulnerabilityName": "Accellion FTA OS Command Injection Vulnerability",
      "dateAdded": "2021-11-03T00:00:00Z",
      "shortDescription": "Accellion FTA contains an OS command injection vulnerability exploited via a crafted POST request to various admin endpoints.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-11-17T00:00:00Z",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    }
  ],
  "vulncheck": [
    {
      "vendorProject": "Accellion",
      "product": "FTA",
      "shortDescription": "Accellion FTA contains an OS command injection vulnerability exploited via a crafted POST request to various admin endpoints.",
      "vulnerabilityName": "Accellion FTA OS Command Injection Vulnerability",
      "required_action": "Apply updates per vendor instructions.",
      "knownRansomwareCampaignUse": "Known",
      "cve": [
        {
          "cveID": "CVE-2021-27104"
        }
      ],
      "vulncheck_xdb": [],
      "vulncheck_reported_exploitation": [
        {
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          "date_added": "2021-11-03T00:00:00Z"
        },
        {
          "url": "https://unit42.paloaltonetworks.com/clop-ransomware/",
          "date_added": "2021-04-13T00:00:00Z"
        },
        {
          "url": "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/ransomware-double-extortion-and-beyond-revil-clop-and-conti",
          "date_added": "2021-06-15T00:00:00Z"
        },
        {
          "url": "https://cybersecurityworks.com/howdymanage/uploads/file/ransomware-_-2022-spotlight-report_compressed.pdf",
          "date_added": "2022-01-26T00:00:00Z"
        },
        {
          "url": "https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/2022-unit42-ransomware-threat-report-final.pdf",
          "date_added": "2022-03-24T00:00:00Z"
        },
        {
          "url": "https://static.tenable.com/marketing/whitepapers/Whitepaper-Ransomware_Ecosystem.pdf",
          "date_added": "2022-06-22T00:00:00Z"
        },
        {
          "url": "https://www.group-ib.com/resources/research-hub/hi-tech-crime-trends-2022/",
          "date_added": "2023-01-17T00:00:00Z"
        },
        {
          "url": "https://fourcore.io/blogs/clop-ransomware-history-adversary-simulation",
          "date_added": "2023-06-03T00:00:00Z"
        },
        {
          "url": "https://blog.talosintelligence.com/talos-ir-q2-2023-quarterly-recap/",
          "date_added": "2023-07-26T00:00:00Z"
        },
        {
          "url": "https://www.sentinelone.com/resources/watchtower-end-of-year-report-2023/",
          "date_added": "2021-11-03T00:00:00Z"
        },
        {
          "url": "https://www.trustwave.com/en-us/resources/blogs/trustwave-blog/defending-the-energy-sector-against-cyber-threats-insights-from-trustwave-spiderlabs/",
          "date_added": "2024-05-15T00:00:00Z"
        },
        {
          "url": "https://cisa.gov/news-events/cybersecurity-advisories/aa21-055a",
          "date_added": "2021-06-17T00:00:00Z"
        },
        {
          "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-209a",
          "date_added": "2021-08-20T00:00:00Z"
        },
        {
          "url": "https://cisa.gov/news-events/alerts/2022/04/27/2021-top-routinely-exploited-vulnerabilities",
          "date_added": "2022-04-28T00:00:00Z"
        },
        {
          "url": "https://cisa.gov/news-events/cybersecurity-advisories/aa22-117a",
          "date_added": "2022-04-28T00:00:00Z"
        },
        {
          "url": "https://www.hhs.gov/sites/default/files/threat-profile-june-2023.pdf",
          "date_added": "2023-06-13T00:00:00Z"
        }
      ],
      "dueDate": "2021-11-17T00:00:00Z",
      "cisa_date_added": "2021-11-03T00:00:00Z",
      "date_added": "2021-04-13T00:00:00Z"
    }
  ]
}
```

# License
MIT

# Author
[MaineK00n](https://twitter.com/MaineK00n)