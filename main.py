import argparse
from colorama import Fore, Style
from core import scanner, cli

def main():
    cli.banner()
    parser = argparse.ArgumentParser(description='Specify scan parameters.')

    parser.add_argument('--all', action='store_true', help='Scanning all package managers')
    parser.add_argument('--packages', type=str, help='Define package manager to test', default="")

    args = parser.parse_args()

    if not args.all and not args.packages:
        parser.error('Please specify either --all or --packages')

    scanner.scan(args)

if __name__ == '__main__':
    main()
