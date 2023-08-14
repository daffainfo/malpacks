import json

with open('/path/to/list/malicious/pkgs.txt', 'r') as file:
    lines = file.read().splitlines()

with open('database.json', 'r') as file:
    existing_data = json.load(file)

for line in lines:
    new_object = {
        "type": "pypi",
        "name": line,
        "url": "https://github.com/DataDog/malicious-software-packages-dataset"
    }
    existing_data.append(new_object)

with open('database_new.json', 'w') as file:
    json.dump(existing_data, file, indent=4)

print("Data appended and saved to database_new.json")

# This script is used to append data to the database.json file