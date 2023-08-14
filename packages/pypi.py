import subprocess

def list_all_pypi_packages():
    try:
        # Run the 'pip freeze' command and capture its output
        result = subprocess.run(['pip3', 'freeze', '--all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            # Split the captured output into lines to get package names
            package_lines = result.stdout.split('\n')

            # Initialize an empty list to store package names
            package_names = []

            # Append package names to the list
            for package_line in package_lines:
                package_name = package_line.split('==')[0]  # Extract the package name
                if package_name:
                    package_names.append(package_name)

            return package_names  # Return the list of package names

        else:
            print("Error:", result.stderr)
    
    except Exception as e:
        print("An error occurred:", e)

# packages_array = list_all_pypi_packages()
# print(packages_array)
