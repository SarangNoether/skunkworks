#  Use chain data to compare transaction protocols protocols
# - Data is expected in a separated text format
# - This version is slow and runs the formulas for each line separately

import argparse
import math

parser = argparse.ArgumentParser(description='Uses chain data to compare transaction protocol estimates', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('data_file', help='data file')
parser.add_argument('--col_block', required=False, type=int, default=0, help='column index for block height')
parser.add_argument('--col_in', required=False, type=int, default=1, help='column index for transaction inputs')
parser.add_argument('--col_out', required=False, type=int, default=2, help='column index for transaction outputs')
parser.add_argument('--col_size', required=False, type=int, default=3, help='column index for transaction size (bytes)')
parser.add_argument('--start', required=False, type=int, default=0, help='starting block height')
parser.add_argument('--headers', required=False, type=int, default=0, help='header lines to ignore in data file')
parser.add_argument('-N', required=False, type=int, default=16, help='ring size')
parser.add_argument('--separator', required=False, default=',', help='column separator')
parser.add_argument('--batch_size', required=False, type=int, default=0, help='batch size (0 is per block)')
args = parser.parse_args()

# Parse parameters
SEPARATOR = args.separator # column separator
COL_BLOCK = args.col_block # block height
COL_INS = args.col_in # input count
COL_OUTS = args.col_out # output count
COL_SIZE = args.col_size # real transaction size
START_BLOCK = args.start # starting block height (<= 0 for all)
HEADERS = args.headers # number of header lines to skip
N = args.N # assumes fixed ring size
BATCH = args.batch_size # 0 is per block, otherwise fixed number of transactions
data = open(args.data_file,'r') # data file

# Size and time data
size = {'triptych':0, 'arcturus':0, 'rct3-single':0, 'rct3-multi':0, 'clsag':0, 'mlsag':0} # in group/field elements
time = {'triptych':0, 'arcturus':0, 'rct3-single':0, 'rct3-multi':0} # in linear combination counts
actual_size = 0 # real chain growth (in bytes)

# Cache data
_logN = math.log2(N)
_log2 = [None] # don't care about `T=0`
for i in range(1,16+1):
    _log2.append(math.ceil(math.log2(64*i)))

# Timing estimates (ms)
def timing(i):
    return float(7572-398)/(190000-10000)*(i-10000)+398

# Triptych
def triptych(M,T):
    total = 0
    total += M*(3*_logN + 8) # spend proofs
    total += M # input key images
    total += M # input auxiliary commitments
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total
def batch_triptych(batch):
    sum_M = sum([datum[0] for datum in batch]) # M_1 + M_2 + ... + M_B
    sum_T = sum([datum[1] for datum in batch]) # T_1 + T_2 + ... + T_B
    max_T = max([datum[1] for datum in batch]) # max(T_1, ..., T_B)
    B = len(batch) # total transactions in batch

    total = 0
    total += _logN*(2 + 2*sum_M) + 2*B*N + 3*sum_M + 2 # spend proofs
    total += sum_M + sum_T # balance checks
    total += 4*B + sum_T + 2*sum([math.log2(64*datum[1]) for datum in batch]) + 128*max_T + 2 # range proofs
    return total

# Arcturus
def arcturus(M,T):
    total = 0
    total += _logN*(M + 3) + M + 7 # spend proof
    total += M # input key images
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total
def batch_arcturus(batch):
    sum_M = sum([datum[0] for datum in batch]) # M_1 + M_2 + ... + M_B
    sum_T = sum([datum[1] for datum in batch]) # T_1 + T_2 + ... + T_B
    max_M = max([datum[0] for datum in batch]) # max(M_1, ..., M_B)
    max_T = max([datum[1] for datum in batch]) # max(T_1, ..., T_B)
    B = len(batch) # total transactions in batch

    total = 0
    total += _logN*(2*max_M + 3*B) + 2*B*N + sum_M + sum_T + 2 # spend proof
    total += 4*B + sum_T + 2*sum([math.log2(64*datum[1]) for datum in batch]) + 128*max_T + 2 # range proofs
    return total

# Single-input RCT3
def rct3_single(M,T):
    total = 0
    total += M*(2*_logN + 18) # spend proofs
    total += 2 # balance proof
    total += M # input key images
    total += M # input auxiliary commitments
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total
def batch_rct3_single(batch):
    sum_M = sum([datum[0] for datum in batch]) # M_1 + M_2 + ... + M_B
    sum_T = sum([datum[1] for datum in batch]) # T_1 + T_2 + ... + T_B
    max_T = max([datum[1] for datum in batch]) # max(T_1, ..., T_B)
    B = len(batch) # total transactions in batch

    total = 0
    total += N*(2*B + 2) + sum_M*(2*_logN + 11) + 5 # spend proofs
    total += sum_M + sum_T + 2 # balance checks
    total += 4*B + sum_T + 2*sum([math.log2(64*datum[1]) for datum in batch]) + 128*max_T + 2 # range proofs
    return total

# Multi-input RCT3
def rct3_multi(M,T):
    total = 0
    total += 2*math.ceil(math.log2(N*M)) + M + 17 # spend proof
    total += M # input key images
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total
def batch_rct3_multi(batch):
    sum_M = sum([2**math.ceil(math.log2(datum[0])) for datum in batch]) # M_1 + M_2 + ... + M_B, each rounded up to power of 2
    sum_T = sum([datum[1] for datum in batch]) # T_1 + T_2 + ... + T_B
    max_M = 2**math.ceil(math.log2(max([datum[0] for datum in batch]))) # max(M_1, ..., M_B), rounded up to power of 2
    max_T = max([datum[1] for datum in batch]) # max(T_1, ..., T_B)
    B = len(batch) # total transactions in batch

    total = 0
    total += N*(2*B + max_M + 1) + 8*B + sum_M + sum_T + 2*sum([math.ceil(math.log2(N*datum[0])) for datum in batch]) + 5 # spend proof
    total += 4*B + sum_T + 2*sum([math.log2(64*datum[1]) for datum in batch]) + 128*max_T + 2 # range proofs
    return total

# CLSAG
def clsag(M,T):
    total = 0
    total += M*(N + 2) # signatures
    total += M # input key images
    total += M # input auxiliary commitments
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total

# MLSAG
def mlsag(M,T):
    total = 0
    total += M*(2*N + 1) # signatures
    total += M # input key images
    total += M # input auxiliary commitments
    total += 2*_log2[T] + 10 # range proof
    total += T # output commitments
    total += T # output public keys
    total += T/4.0 # output amounts
    total += T # transaction keys
    total += 1 # payment ID
    return total

start_flag = False # have we reached the starting height yet?
batch_data = [] # current batch data: [[M_1,T_1],[M_2,T_2],...]
batch_height = None # current batch height

# Skip headers
for _ in range(HEADERS):
    data.readline()

# Parse data
for line in data:
    line = line.strip().split(SEPARATOR)

    # Test for height
    if not start_flag:
        if int(line[COL_BLOCK]) < START_BLOCK:
            continue
        batch_height = int(line[COL_BLOCK]) # start batching now
        start_flag = True

    # Run size computations
    ins = int(line[COL_INS])
    outs = int(line[COL_OUTS])
    size['triptych'] += triptych(ins,outs)
    size['arcturus'] += arcturus(ins,outs)
    size['rct3-single'] += rct3_single(ins,outs)
    size['rct3-multi'] += rct3_multi(ins,outs)
    size['clsag'] += clsag(ins,outs)
    size['mlsag'] += mlsag(ins,outs)
    actual_size += int(line[COL_SIZE])

    # Check batch data
    if (BATCH == 0 and int(line[COL_BLOCK]) == batch_height) or (BATCH > 0 and len(batch_data) < BATCH): # still on the same batch
        batch_data.append([int(line[COL_INS]),int(line[COL_OUTS])])
    else: # new batch, who dis
        time['triptych'] += timing(batch_triptych(batch_data)) # process the batch
        time['arcturus'] += timing(batch_arcturus(batch_data)) # process the batch
        time['rct3-single'] += timing(batch_rct3_single(batch_data)) # process the batch
        time['rct3-multi'] += timing(batch_rct3_multi(batch_data)) # process the batch
        batch_data = []
        batch_data.append([int(line[COL_INS]),int(line[COL_OUTS])]) # start the next batch
        batch_height = int(line[COL_BLOCK])

# Output total sizes
print('Size data (GB)')
print('--------------')
print('actual','\t',round(actual_size/1024/1024/1024,2)) # GB
for protocol in sorted(size.keys()):
    print(protocol,'\t',round(size[protocol]*32/1024/1024/1024,2)) # sizes are scaled from field/group elements to GB
print()
print('Time data (hours)')
print('-----------------')
for protocol in sorted(time.keys()):
    print(protocol,'\t',round(time[protocol]/1000/60/60,2)) # hours
