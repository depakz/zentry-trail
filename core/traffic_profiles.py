"""Browser Profile Definitions."""

PROFILES = {
    "chrome124": {
        "Host": "",
        "Connection": "keep-alive",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "header_order": [
            "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
            "Accept-Language"
        ]
    },
    "firefox124": {
        "Host": "",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "header_order": [
            "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
            "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
            "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"
        ]
    },
    "safari17": {
        "Host": "",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "header_order": [
            "Host", "Accept", "User-Agent", "Accept-Language", "Accept-Encoding",
            "Connection", "Upgrade-Insecure-Requests"
        ]
    }
}