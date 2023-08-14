import json
from colorama import Fore, Style
from packages import npm, pypi, gem

npm_packages = []
pypi_packages = []
gem_packages = []

def scan(args):

    if args.all:
        npm_packages = npm.list_all_npm_packages()
        pypi_packages = pypi.list_all_pypi_packages()
        gem_packages = gem.list_all_gem_packages()
        check('npm', npm_packages)
        check('pypi', pypi_packages)
        check('gem', gem_packages)

    if args.packages:
        packages_type = args.packages.split(',')
        for package_type in packages_type:
            if package_type == 'npm':
                npm_packages = npm.list_all_npm_packages()
                check('npm', npm_packages)
            elif package_type == 'pypi':
                pypi_packages = pypi.list_all_pypi_packages()
                check('pypi', pypi_packages)
            elif package_type == 'gem':
                gem_packages = gem.list_all_gem_packages()
                check('gem', gem_packages)
            else:
                print(Fore.RED + f"[!] Unknown package type: {package_type}")
                print(Style.RESET_ALL)

def check(package_type, package_names):
    with open('database.json') as json_file:
        database = json.load(json_file)

    print(Fore.YELLOW + f"[!] Checking {package_type} packages...")

    found_count = 0
    for package in database:
        package_type_in_db = package.get('type', '')
        package_name = package.get('name', '')
        package_url = package.get('url', '')

        if package_type == package_type_in_db and package_name in package_names:
            print(Fore.RED + f"[+] Package found: {package_name}")
            print(Fore.RED + f"[+] Advisory: {package_url}")
            print(Style.RESET_ALL)
            found_count = found_count + 1

    if found_count == 0:
        print(Fore.GREEN + f"[+] No malicious {package_type} packages found.")
        print(Style.RESET_ALL)