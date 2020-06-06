import argparse

parser = argparse.ArgumentParser(description='Compute the number of confidential inputs susceptible to tracing')
parser.add_argument('--transactions',type=argparse.FileType('r'),help='input file path containing block data',required=True)
parser.add_argument('--tracing',type=argparse.FileType('r'),help='input file path containing trace data',required=True)
parser.add_argument('--status',type=bool,default=False,help='whether or not to display status information during processing')
args = parser.parse_args()

modes = {}

# Process blocks for all confidential transactions
count = 0
if args.status:
    print('Processing blocks...')
for tx in args.transactions:
    count += 1
    tx = tx.strip().split(' ')
    modes[tx[0]] = tx[2]
if args.status:
    print('Processed',count,'transactions')

# Parse tracing data
count = 0
hits = 0
if args.status:
    print('Parsing tracing data for these transactions...')
for trace in args.tracing:
    count += 1
    trace = trace.strip().split(' ')
    if modes[trace[0]] == "3":
        hits += 1

if args.status:
    print('Processed',count,'traced inputs')
    print('Found',hits,'traced confidential inputs')
