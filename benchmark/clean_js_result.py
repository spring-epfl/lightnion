import sys

file_name = sys.argv[1]
with open(file_name, "r") as file:
	content = file.read()
new_content = []
for line in content.split("\n"):
	sp = line.find(" ")
	new_content.append(line[sp+1:])

with open(file_name+"_cleaned", "a") as file:
	for res in new_content:
		file.write(res+'\n')
