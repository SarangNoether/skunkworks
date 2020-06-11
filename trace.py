from sys import version_info

if version_info[0] != 3:
    raise Exception('This tool requires Python 3!')

import argparse

parser = argparse.ArgumentParser(description='Use ring data to iteratively identify traced transaction inputs')
parser.add_argument('--file_transactions',type=argparse.FileType('r'),help='input file path containing transaction data',required=True)
parser.add_argument('--file_rings',type=argparse.FileType('r'),help='input file path containing ring data',required=True)
parser.add_argument('--file_trace',type=argparse.FileType('x'),help='output file path for trace data',required=True)
args = parser.parse_args()

transactions = {}
lookups = {}

# Parse transaction data for lookup purposes
print('Processing transaction data...')
for line in args.file_transactions:
    line = line.strip().split(' ')
    lookups[int(line[0])] = line
args.file_transactions.close()

# Parse rings for each transaction
print('Processing ring data...')
for ring in args.file_rings:
    ring = ring.strip().split(' ')
    index = int(ring[0])
    if index not in transactions:
        transactions[index] = {}
    transactions[index][ring[1]] = ring[2:]
args.file_rings.close()

done = False
iterations = 0
marked_transactions = set()

# Iterate to identify traced rings
while not done:
    iterations += 1
    print('Iteration {}: '.format(iterations),end='')
    done = True
    marked_keys = set() # keys to be removed
    marked_rings = set() # inputs to be removed

    # Find all single-key rings
    for transaction in transactions:
        for ring in transactions[transaction]:
            if len(transactions[transaction][ring]) == 1:
                marked_keys.add(transactions[transaction][ring][0])
                marked_rings.add((transaction,ring))
                done = False
    print('marked {} rings'.format(len(marked_rings)))

    # Delete all marked keys from all remaining rings
    for transaction in transactions:
        for ring in transactions[transaction]:
            transactions[transaction][ring] = [key for key in transactions[transaction][ring] if key not in marked_keys]

    # Delete all marked rings
    for marked_ring in marked_rings:
        transactions[marked_ring[0]].pop(marked_ring[1])
        if marked_ring[0] in marked_transactions:
            continue
        marked_transactions.add(marked_ring[0])

# Order by transaction index
for index in sorted(marked_transactions):
    print(' '.join(lookups[index]),file=args.file_trace)
args.file_trace.close()
