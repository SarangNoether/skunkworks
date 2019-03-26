#
# Simulate different ring member selection algorithms
#
# - This code is for research purposes only.
# - This code is released into the public domain with no warranty.

import numpy
import argparse
import sys

# Check version
if sys.version_info[0] < 3:
    raise RuntimeError('Must use Python 3!')

# Parse options
parser = argparse.ArgumentParser(description='Simulate ring member selection')
parser.add_argument('--chain_size',default=500000,type=int,help='Number of blocks in the chain')
parser.add_argument('--block_time',default=120,type=int,help='Block time in seconds')
parser.add_argument('--chain_data',help='Path to chain data file; each line is the number of outputs in a block')
parser.add_argument('--window',default=5,type=int,help='Number of blocks in half window')
parser.add_argument('--lineup_window',default=0,type=int,help='Number of blocks in output lineup window')
parser.add_argument('-N',default=10000,type=int,help='Number of outputs to select')
parser.add_argument('--density',required=True,choices=['real','geometric','feast','famine'],help='Chain density model')
parser.add_argument('--selection',required=True,choices=['partial','full','lineup','bias'],help='Output selection algorithm')
parser.add_argument('--types',default=5,type=int,help='Number of output types to track')
args = parser.parse_args()

# Python3 rounding is silly
def rnd(x,n):
    return int(round(x*(10**n)))/10**n

# Distribution constants
GAMMA_SHAPE = 19.28
GAMMA_SCALE = 1.0/1.61
GEOMETRIC_P = 0.25

# Generate a chain using the desired density
def generate_chain():
    print('Using chain density',args.density)

    if args.density == 'real':
        try:
            infile = open(args.chain_data,'r')
        except:
            raise Exception('Bad chain data file!')
        temp = []
        for line in infile:
            temp.append(int(line.strip()))
        chain = []
        while len(chain) < args.chain_size:
            chain.extend(temp)

        return chain[:args.chain_size]

    elif args.density == 'geometric':
        return list(numpy.random.geometric(GEOMETRIC_P,args.chain_size))

    elif args.density == 'famine':
        mean = int(numpy.exp(GAMMA_SCALE*GAMMA_SHAPE)/args.block_time) # mean of gamma distribution
        temp = [1]*mean # empty head
        temp.extend(list(numpy.random.geometric(GEOMETRIC_P,args.chain_size-mean))) # tail
        return temp

    elif args.density == 'feast':
        mean = int(numpy.exp(GAMMA_SCALE*GAMMA_SHAPE)/args.block_time) # mean of gamma distribution
        temp = list(numpy.random.geometric(GEOMETRIC_P,mean)) # head
        temp.extend([1]*(args.chain_size-mean)) # empty tail
        return temp

    raise Exception('Invalid chain model!')

# Make a gamma selection
def gamma():
    return numpy.random.gamma(shape=GAMMA_SHAPE,scale=GAMMA_SCALE)

# Make a selection using a partial-window method
def select_partial():
    # Keep trying until we select a valid block
    while True:
        index = int(numpy.exp(gamma())/args.block_time) # block index, assuming constant arrival time
        if index >= args.chain_size: # trying to select too far back
            continue
        if chain[index] == 0: # a truly empty block; redraw
            continue
        break

    # Now select an output uniformly within the block and a partial window
    window_offset = 0
    for i in range(args.window):
        if index-i == 0 or index+i == args.chain_size-1:
            break
        if chain[index-i] > 1 or chain[index+i] > 1:
            break
        window_offset += 1

    window_outputs = sum([chain[i] for i in range(index-window_offset,index+window_offset+1)])
    if numpy.random.randint(0,window_outputs) < 2*window_offset+1:
        coinbase = True
    else:
        coinbase = False

    return index,coinbase

# Make a selection using a full-window method
def select_full():
    # Keep trying until we select a valid block
    while True:
        index = int(numpy.exp(gamma())/args.block_time) # block index, assuming constant arrival time
        if index >= args.chain_size: # trying to select too far back
            continue
        if chain[index] == 0: # a truly empty block; redraw
            continue
        break

    # Now select an output uniformly within the block and a partial window
    window_low = max(index-args.window,0)
    window_high = min(index+args.window,args.chain_size)

    window_outputs = sum([chain[i] for i in range(window_low,window_high+1)])
    if numpy.random.randint(0,window_outputs) < (window_high-window_low+1):
        coinbase = True
    else:
        coinbase = False

    return index,coinbase

# Make a selection using an output-lineup method
def select_lineup():
    output_time = args.block_time*args.lineup_window/window_sum # average time per output

    # Keep trying until we select a valid output
    while True:
        index_output = int(numpy.exp(gamma())/output_time) # output index, assuming constant arrival time
        if index_output >= chain_sum: # trying to select too far back
            continue
        else:
            break

    # Determine the block index
    index = 0
    tally = 0
    while tally < index_output:
        index += 1
        tally += chain[index]

    # Now select an output uniformly within the block
    if numpy.random.randint(0,chain[index]) == 0:
        coinbase = True
    else:
        coinbase = False

    return index,coinbase

# Make a selection using an output-lineup bias method
def select_bias():
    # Keep trying until we select a valid block
    while True:
        index = int(numpy.exp(gamma())/args.block_time) # block index, assuming constant arrival time
        if index >= args.chain_size: # trying to select too far back
            continue
        else:
            break

    # Determine the highest output index in the range
    index_output = 0
    block_range = min(args.chain_size,2*index+2)
    for i in range(block_range):
        index_output += chain[i]

    # Now select an output uniformly within the range
    if numpy.random.randint(0,index_output) < block_range:
        coinbase = True
    else:
        coinbase = False

    return index,coinbase


#
# HERE WE GO
#

# Initialize the chain
print('Initializing chain...')
chain = generate_chain()
chain_sum = sum(chain) # total outputs on the chain
if args.lineup_window == 0 or args.lineup_window >= len(chain):
    window_sum = chain_sum
else:
    window_sum = sum(chain[:args.lineup_window])
chain_types = [0]*args.types # outputs on the chain by type
for i in chain:
    if i in range(1,args.types+1):
        chain_types[i-1] += i

calc_less_than_mean = 0 # number of ring members whose block is newer than the gamma mean
calc_coinbase = 0 # number of selected ring members that are coinbase
calc_type = [0]*args.types # output types in selection

print('Selecting ring members...')
print('Using selection algorithm',args.selection)
print('Selecting',args.N,'outputs from chain size',len(chain))
for i in range(args.N):
    # Selection model
    if args.selection == 'partial':
        index,coinbase = select_partial()
    elif args.selection == 'full':
        index,coinbase = select_full()
    elif args.selection == 'lineup':
        index,coinbase = select_lineup()
    elif args.selection == 'bias':
        index,coinbase = select_bias()

    # Mean check
    if index < int(numpy.exp(GAMMA_SHAPE*GAMMA_SCALE)/args.block_time):
        calc_less_than_mean += 1

    # Coinbase check
    if coinbase:
        calc_coinbase += 1

    # Type check
    if chain[index] in range(1,args.types+1):
        calc_type[chain[index]-1] += 1

# Output statistics
print('Block ages less than mean:',rnd(calc_less_than_mean/args.N,4))
print('Coinbase in selection:',rnd(calc_coinbase/args.N,4))
print('Coinbase on chain:',rnd(args.chain_size/sum(chain),4))
print('Types in selection:',[rnd(calc_type[i]/args.N,4) for i in range(len(calc_type))])
print('Types on chain:',[rnd(chain_types[i]/sum(chain),4) for i in range(args.types)])
