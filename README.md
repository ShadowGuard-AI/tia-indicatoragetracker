# tia-IndicatorAgeTracker
A command-line tool that tracks the age (first seen date) of indicators of compromise (IOCs).  It accepts a list of IOCs and queries public threat intelligence sources like Shodan and Censys to find when they were first observed.  Reports IOCs that are significantly older than average, which may indicate stale intelligence or persistent threats. - Focused on Aggregates threat intelligence data from various open-source feeds (e.g., lists of malicious IPs, URLs, domain names). Parses and normalizes the data into a consistent format for analysis and alerting. Designed for efficient querying and integration with other security tools. Uses web scraping and API calls.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-indicatoragetracker`

## Usage
`./tia-indicatoragetracker [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: No description provided
- `--shodan-api-key`: Shodan API key for looking up IP addresses.  Can also be specified via the SHODAN_API_KEY environment variable.
- `--censys-api-id`: Censys API ID for looking up domains. Can also be specified via the CENSYS_API_ID environment variable.
- `--censys-api-secret`: Censys API secret for looking up domains. Can also be specified via the CENSYS_API_SECRET environment variable.

## License
Copyright (c) ShadowStrikeHQ
