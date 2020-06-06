import argparse

parser = argparse.ArgumentParser(description='Use ring data to iteratively identify traced transaction inputs')
parser.add_argument('--input',type=argparse.FileType('r'),help='input file path containing ring data',required=True)
parser.add_argument('--output',type=argparse.FileType('x'),help='output file path (for safety, cannot already exist)',required=True)
parser.add_argument('--status',type=bool,default=False,help='whether or not to display status information during processing')
args = parser.parse_args()

transactions = {}

# Parse ring members for each transaction input
if args.status:
    print('Processing input file...')
for line in args.input:
    line = line.strip().split(' ')
    transaction = int(line[0])
    if transaction not in transactions:
        transactions[transaction] = {}
    transactions[transaction][line[1]] = line[2:]

done = False
iterations = 0 # iterations

# Iterate to identify traced transaction inputs
while not done:
    if args.status:
        iterations += 1
        print('Starting iteration',iterations)
    done = True
    marked_keys = set() # keys to be removed
    marked_inputs = set() # inputs to be removed

    # Find all single-key transaction inputs; these are traced
    if args.status:
        print('  Finding traced transaction inputs...')
    for transaction in transactions:
        for ring in transactions[transaction]:
            if len(transactions[transaction][ring]) == 1:
                marked_keys.add(transactions[transaction][ring][0])
                marked_inputs.add((transaction,ring))
                done = False
    if args.status:
        print('  Traced',len(marked_inputs),'new transaction inputs')

    # Delete all marked keys from all remaining inputs
    if args.status:
        print('  Propagating to rings...')
    for transaction in transactions:
        for ring in transactions[transaction]:
            transactions[transaction][ring] = [key for key in transactions[transaction][ring] if key not in marked_keys]

    # Delete all marked inputs
    for marked_input in marked_inputs:
        transactions[marked_input[0]].pop(marked_input[1])
        print(marked_input[0],marked_input[1],file=args.output)
