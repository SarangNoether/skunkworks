from sys import version_info

if version_info[0] != 3:
    raise Exception('This tool requires Python 3!')

import argparse

parser = argparse.ArgumentParser(description='Use deducibility analysis to compute a distribution of coinbase spend ages')
parser.add_argument('--file_transactions',type=argparse.FileType('r'),help='input file path containing transaction data',required=True)
parser.add_argument('--file_outputs',type=argparse.FileType('r'),help='input file path containing output data',required=True)
parser.add_argument('--file_rings',type=argparse.FileType('r'),help='input file path containing ring data',required=True)
parser.add_argument('--file_dist',type=argparse.FileType('x'),help='output file path for distribution data',required=True)
args = parser.parse_args()

ring_data = {}
output_data = {}
transaction_data = {}

# Parse transaction data
print('Processing transaction data...')
for line in args.file_transactions:
    line = line.strip().split(' ')
    transaction_data[line[0]] = line # includes txid
args.file_transactions.close()

# Parse output data by key
print('Processing output data...')
for line in args.file_outputs:
    line = line.strip().split(' ')
    for output in line[1:]:
        output_data[output] = line[0]
args.file_outputs.close()

# Parse ring data
print('Processing ring data...')
for ring in args.file_rings:
    ring = ring.strip().split(' ')
    index = ring[0]
    if index not in ring_data:
        ring_data[index] = {}
    ring_data[index][ring[1]] = ring[2:]
args.file_rings.close()

done = False
iterations = 0
deducible_keys = [] # [txid, key]

# Iterate to identify traced rings
while not done:
    iterations += 1
    print('Iteration {}: '.format(iterations),end='')
    done = True
    marked_keys = set() # keys to be removed
    marked_rings = set() # inputs to be removed

    # Find all single-key rings
    for transaction in ring_data:
        for ring in ring_data[transaction]:
            if len(ring_data[transaction][ring]) == 1:
                marked_keys.add(ring_data[transaction][ring][0])
                marked_rings.add((transaction,ring))
                deducible_keys.append([transaction,ring_data[transaction][ring][0]])
                done = False
    print('marked {} rings'.format(len(marked_rings)))

    # Delete all marked keys from all remaining rings
    for transaction in ring_data:
        for ring in ring_data[transaction]:
            ring_data[transaction][ring] = [key for key in ring_data[transaction][ring] if key not in marked_keys]

    # Delete all marked rings
    for marked_ring in marked_rings:
        ring_data[marked_ring[0]].pop(marked_ring[1])

# For each deduced key, identify:
#   destination transaction height
#   source transaction index
#   source transaction mode
#   source transaction height
# If coinbase, compute the height difference as the spend age
# To examine other transaction modes, change the mode filter below
print('Scanning for coinbase transactions...')
for deducible_key in deducible_keys:
    source_index = output_data[deducible_key[1]]
    destination_index = deducible_key[0]
    if transaction_data[source_index][2] == '0': # coinbase
        print(transaction_data[source_index][1],transaction_data[destination_index][1],int(transaction_data[destination_index][1]) - int(transaction_data[source_index][1]),file=args.file_dist) # source_height destination_height age
