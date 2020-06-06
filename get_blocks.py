import requests
import argparse

parser = argparse.ArgumentParser(description='Fetch and parse block and transaction data')
parser.add_argument('--start',type=int,default=0,help='starting block height')
parser.add_argument('--end',type=int,default=0,help='ending block height',required=True)
parser.add_argument('--server',help='server IP or DNS value',required=True)
parser.add_argument('--port',type=int,default=8081,help='listening port on the server')
parser.add_argument('--tls',type=bool,default=False,help='whether to use a TLS connection to the server')
parser.add_argument('--output',type=argparse.FileType('x'),help='output file path (for safety, cannot already exist)',required=True)
parser.add_argument('--status',type=int,default=0,help='how often (in blocks) to output status (0 to disable)')
args = parser.parse_args()

# Transaction modes
MODE_COINBASE = 0
MODE_CLEAR = 1 # tx_version == 1
MODE_SEMI = 2 # tx_version == 2 and xmr_inputs != 0
MODE_OPAQUE = 3 # tx_version == 2 and xmr_inputs == 0

# Input sanity checks
if not args.end >= args.start:
    raise ValueError('Ending block height must be at least the starting block height!')
if args.port < 0 or args.port > 65535:
    raise ValueError('Invalid port number!')
if args.status < 0:
    raise ValueError('Invalid status frequency!')

session = requests.Session()
counter = 0

# Process each block
for height in range(args.start,args.end+1):
    # Status update
    if args.status > 0 and (height - args.start) % args.status == 0:
            print('Processing block',height,'of',args.end)

    result = session.get('{}://{}:{}/api/block/{}'.format('https' if args.tls else 'http',args.server,args.port,height)).json()['data']
    for transaction in result['txs']:
        mode = MODE_COINBASE
        if not transaction['coinbase']:
            if transaction['tx_version'] == 1:
                mode = MODE_CLEAR
            elif transaction['tx_version'] == 2 and transaction['xmr_inputs'] != 0:
                mode = MODE_SEMI
            else:
                mode = MODE_OPAQUE
        print(counter,height,mode,transaction['tx_hash'],file=args.output)
        counter += 1
