# Fastscan

    pip install aiohttp

# Basic Nikto-style scan

    python fastscan.py -h https://example.com

# Force SSL on a custom port, HTML report

    python fastscan.py -h example.com -p 8443 -s -o report.html -F html

# Only info-disclosure + admin consoles, high concurrency

    python fastscan.py -h https://example.com -T 35e -c 100

# Everything except SQLi and DoS, with auth and a wordlist

    python fastscan.py -h https://example.com -Tx96 --auth admin:secret -w paths.txt -o out.json -F json
