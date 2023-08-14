import subprocess

def list_all_gem_packages():
    try:
        result = subprocess.run(['gem', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            # Split the captured output into lines to get package lines
            package_lines = result.stdout.split('\n')

            # Initialize an empty list to store package names
            package_names = []

            # Print only the package names
            for package_line in package_lines:
                package_info = package_line.strip().split(' ')
                if len(package_info) > 0:
                    package_name = package_info[0]
                    package_names.append(package_name)
            
            return package_names  # Return the list of package names

        else:
            print("Error:", result.stderr)

    except Exception as e:
        print("An error occurred:", e)

# packages_array = list_all_gem_packages()
# print(packages_array)
