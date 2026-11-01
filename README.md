# tia-IndicatorAgeTracker

A command-line tool that tracks the age (first seen date) of indicators of compromise (IOCs). It accepts a list of IOCs and queries Shodan (api.shodan.io) and Censys (search.censys.io), both named here, to find when they were first observed, and reports IOCs whose age is significantly above the batch average, which may indicate stale intelligence or persistent threats.

The Shodan API key is supplied only through the SHODAN_API_KEY environment variable; there is no command-line key argument. The key is sent in an Authorization header (HTTP Basic with the key as the username and an empty password, per Shodan's documented API auth), never in the URL query string, so it does not land in server or proxy logs. Censys credentials are sent with HTTP Basic auth as well, from the CENSYS_API_ID and CENSYS_API_SECRET environment variables or the command-line arguments below. All API requests carry a 10 second timeout.

Timestamps returned by either source are normalized to timezone-aware UTC before any arithmetic. An IOC's age is computed as now minus its first seen date and is logged as a duration; the headline figure is the mean of those ages.

A run with no credentials configured performs zero lookups and exits non-zero with an explicit not-performed message. A run that collects no ages also exits non-zero.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-indicatoragetracker`

## Usage
`SHODAN_API_KEY=your_key python main.py -i 8.8.8.8 example.com`

## Parameters
- `-h`: Show help message and exit
- `-i`: List of IOCs (IP addresses, domains, etc.) to check
- `--censys-api-id`: Censys API ID for looking up domains. Can also be specified via the CENSYS_API_ID environment variable.
- `--censys-api-secret`: Censys API secret for looking up domains. Can also be specified via the CENSYS_API_SECRET environment variable.

## License
Copyright (c) ShadowStrikeHQ
