import sys

def fileToDict(file_path):
    with open(file_path) as file:
        d = {}
        for line in file:
            splited = line.split()       
            for word in splited:           
                if word in d:
                    d[word] += 1
                else:
                    d[word] = 1 
        return d

# creates a dictionary of the words and how many of each word
n = int(sys.argv[-1])
file_path = "WordCounter\Text"
dict = fileToDict(file_path)

# sorts the words and puts them in an array
sorted_words = [word for word, count in sorted(dict.items(), key=lambda item: item[1], reverse=True)]

# prints the common words
for i in range(n):
    if(i<=len(sorted_words)-1): # if N bigger then the Number of the words -> stop
        print(f"{i+1} - word '{sorted_words[i]}' {dict[sorted_words[i]]} times")
    else:
        break