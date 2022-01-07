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
      --debug               debug mode (default: false)
  -h, --help                help for go-kev
      --http-proxy string   http://proxy-url:port (default: empty)
      --log-dir string      /path/to/log (default "/var/log/go-kev")
      --log-json            output log as JSON
      --log-to-file         output log to file

Use "go-kev [command] --help" for more information about a command.
```

# Fetch Known Exploited Vulnerabilities
```console
$ go-kev fetch kevuln
INFO[11-16|04:39:00] Fetching Known Exploited Vulnerabilities 
INFO[11-16|04:39:00] Fetching                                 URL=https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
INFO[11-16|04:39:00] Insert Known Exploited Vulnerabilities into go-kev. db=sqlite3
INFO[11-16|04:39:00] Inserting Known Exploited Vulnerabilities... 
291 / 291 [------------------------------------------------------------------------------] 100.00% ? p/s
INFO[11-16|04:39:00] CveID Count                              count=291
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
[
  {
    "CveID": "CVE-2021-27104",
    "Source": "Accellion",
    "Product": "FTA",
    "Title": "Accellion FTA OS Command Injection Vulnerability",
    "AddedDate": "2021-11-03T00:00:00Z",
    "Description": "Accellion FTA 9_12_370 and earlier is affected by OS command execution via a crafted POST request to various admin endpoints.",
    "Action": "Apply updates per vendor instructions.",
    "DueDate": "2021-11-17T00:00:00Z",
    "Notes": ""
  }
]
```

# License
MIT

# Author
[MaineK00n](https://twitter.com/MaineK00n)