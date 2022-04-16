import sys, json
import names

nodes = set()
users = set()

for cf in sys.argv[1:]:
    with open(cf, "r") as f:
        data = json.loads(f.read())

        nodes |= set(data["nodes"])
        users |= set(data["users"].keys())

nusers = {}
for user in users:
    nusers[user] = names.get_name(names.FILES["first:female"]).lower().capitalize() + " " + names.get_name(names.FILES["last"]).lower().capitalize()

data = json.dumps({"nodes": list(nodes), "users": nusers}, indent=2)

for cf in sys.argv[1:]:
    with open(cf, "w") as f:
        f.write(data)
