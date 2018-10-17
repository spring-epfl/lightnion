if __name__ == "__main__":

    with open("./test.txt", "r") as file:
        raw_text = file.read().split("\n")
        print(len(raw_text))

        for line in raw_text:
            print(line)
            print("\n")
