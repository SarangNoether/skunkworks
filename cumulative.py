from sys import argv
import math

infile = open(argv[1],'r')
precision = int(argv[2])
try:
    start = int(argv[3]) # starting block
    stop = int(argv[4]) # ending block
except:
    start = None
    stop = None

# Pull data
print('Parsing data...')
CROSSOVER = 1009827
data = [] # age in seconds
for line in infile:
    line = line.strip().split(' ')
    line = [int(item) for item in line]

    # Check for range, if specified
    if line[1] < start or line[1] > stop:
        continue

    if line[0] < CROSSOVER and line[1] < CROSSOVER:
        data.append(60*(line[1] - line[0]))
    elif line[0] < CROSSOVER and line[1] > CROSSOVER:
        data.append(60*(CROSSOVER - line[0]) + 120*(line[1] - CROSSOVER))
    else:
        data.append(120*(line[1] - line[0]))

# Statistics
data.sort()
normalizer = len(data)

# Build cumulative distribution
print('Building distribution...')
distribution = {}
cutoff = 0
total = 0
for datum in data:
    if datum >= cutoff:
        distribution[cutoff] = total / normalizer
        cutoff += precision
    total += 1
distribution[cutoff] = total / normalizer

for key in sorted(distribution.keys()):
    print(key,distribution[key])
