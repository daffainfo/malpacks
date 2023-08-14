import subprocess

def list_all_npm_packages():
    try:
        result = subprocess.run(['npm', 'ls', '-g'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            # Split the captured output into lines to get package lines
            package_lines = result.stdout.split('\n')

            # Initialize an empty list to store package names
            package_names = []

            # Print only the package names without directory structure
            for package_line in package_lines:
                package_name = package_line.strip()
                if package_name and package_name != '/usr/local/lib':
                    package_name = package_line.split('@')[0].strip()
                    package_name = package_name.replace('├──', '').replace('└──', '').strip()
                    if package_name:
                        package_names.append(package_name)
            
            return package_names  # Return the list of package names

        else:
            print("Error:", result.stderr)

    except Exception as e:
        print("An error occurred:", e)

#packages_array = list_all_npm_packages()
#print(packages_array)
