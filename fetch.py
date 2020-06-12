from sys import version_info

if version_info[0] != 3:
    raise Exception('This tool requires Python 3!')

import requests
import argparse
import os

parser = argparse.ArgumentParser(description='Fetch and parse an updated transaction list')
parser.add_argument('--server',help='server IP or domain',required=True)
parser.add_argument('--port',type=int,default=8081,help='listening port on the server')
parser.add_argument('--tls',type=bool,default=False,help='whether to use a TLS connection to the server')
parser.add_argument('--file_transactions',type=str,help='output file path for transaction data',required=True)
parser.add_argument('--file_rings',type=str,help='output file path for ring data',required=True)
parser.add_argument('--file_outputs',type=str,help='output file path for output data',required=True)
args = parser.parse_args()

session = requests.Session()

# Transaction modes
MODE_COINBASE = 0
MODE_CLEAR = 1 # tx_version == 1
MODE_SEMI = 2 # tx_version == 2 and xmr_inputs != 0
MODE_OPAQUE = 3 # tx_version == 2 and xmr_inputs == 0

# If the file already exists, find the last block it processed
transaction_index = 0 # transaction index
last_block = -1
try:
    # The file already exists
    last_line = None
    with open(args.file_transactions,'rb') as f:
        f.seek(-2,os.SEEK_END)
        while f.read(1) != b'\n':
            f.seek(-2,os.SEEK_CUR)
        last_line = f.readline().decode().strip().split(' ')

    transaction_index = int(last_line[0]) + 1
    last_block = int(last_line[1])
except:
    # The file does not already exist
    pass

# Get the current height (need to offset by 1 to get most recent block)
try:
    current_block = int(session.get('{}://{}:{}/api/networkinfo'.format('https' if args.tls else 'http',args.server,args.port)).json()['data']['height']) - 1
except:
    raise Exception('Server did not respond to initial height query! This can happen; just run the tool again.')

# See if we're already updated (or past the server)
if last_block >= current_block:
    print('Already up to date! Nothing more to do.')
    sys.exit(0)

# Process each block
with open(args.file_transactions,'a') as file_transactions, open(args.file_rings,'a') as file_rings, open(args.file_outputs,'a') as file_outputs:
    for block in range(last_block+1,current_block+1):
        data_transactions = [] # we write data a block at a time
        data_rings = []
        data_outputs = []

        # Status update
        if block % 10 == 0:
            print('Processed {:.2%} of chain ({}/{} blocks)'.format(block/current_block,block,current_block),end='\r')

        # Fetch all transactions in the block
        result_block = session.get('{}://{}:{}/api/block/{}'.format('https' if args.tls else 'http',args.server,args.port,block)).json()['data']
        for transaction in result_block['txs']:
            # Parse mode data
            mode = MODE_COINBASE
            if not transaction['coinbase']:
                if transaction['tx_version'] == 1:
                    mode = MODE_CLEAR
                elif transaction['tx_version'] == 2 and transaction['xmr_inputs'] != 0:
                    mode = MODE_SEMI
                else:
                    mode = MODE_OPAQUE
            data_transactions.append('{} {} {} {}'.format(transaction_index,block,mode,transaction['tx_hash']))
            transaction_index += 1

            # Get graph data
            result_transaction = session.get('{}://{}:{}/api/transaction/{}'.format('https' if args.tls else 'http',args.server,args.port,transaction['tx_hash'])).json()['data']
            if not result_transaction['coinbase']:
                for ring_index,ring in enumerate(result_transaction['inputs']):
                    data_rings.append('{} {} {}'.format(transaction_index,ring_index,' '.join([mixin['public_key'] for mixin in ring['mixins']])))
            if result_transaction['outputs']:
                data_outputs.append('{} {}'.format(transaction_index,' '.join([output['public_key'] for output in result_transaction['outputs']])))

        # Write all data for this block at once
        try:
            print('\n'.join(data_transactions),file=file_transactions)
            if len(data_rings) > 0:
                print('\n'.join(data_rings),file=file_rings)
            print('\n'.join(data_outputs),file=file_outputs)
        except KeyboardInterrupt:
            # We don't assume atomicity, so warn the user if the write might be bad
            raise Exception('***WARNING*** File writes may be incomplete! You should manually check the data files.')

print()
print('Done!')
