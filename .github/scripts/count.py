import json

with open("../../database.json", "r") as json_file:
    data = json.load(json_file)

type_counts = {}

for item in data:
    item_type = item.get("type")
    if item_type:
        if item_type in type_counts:
            type_counts[item_type] += 1
        else:
            type_counts[item_type] = 1

for item_type, count in type_counts.items():
    print(f"{item_type}: {count}")
