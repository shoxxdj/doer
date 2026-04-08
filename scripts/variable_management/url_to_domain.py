#!/usr/bin/env python3
import sys
from urllib.parse import urlparse

def main():
    if len(sys.argv)<2:
        print("Usage : url_to_domain.py URL")
        sys.exit(1)

    url = sys.argv[1]

    if( "://" not in url):
        print(url.strip())
    else:
        print(urlparse(url).netloc)

if __name__ == '__main__':
    main()