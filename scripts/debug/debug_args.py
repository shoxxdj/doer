#!/usr/bin/env python3
import sys

def main():
    if len(sys.argv)<2:
        print("Usage : debug.py content")
        sys.exit(1)
    print(sys.argv[1])


if __name__ == '__main__':
    main()
