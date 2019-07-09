import sys

file_name = sys.argv[1]

with open(file_name, "r") as file:
    content = file.read()

content = content.split(" in ")[1:]
time = []
for c in content:
    time.append(c[:5])

with open(file_name+"_result", "a") as file:
    for t in time:
        t = t.replace(".", ",")
        file.write(t+"\n")

