import requests
import argparse

parser = argparse.ArgumentParser(description='Use block and transaction data to fetch and parse ring data')
parser.add_argument('--server',help='server IP or DNS value',required=True)
parser.add_argument('--port',type=int,default=8081,help='listening port on the server')
parser.add_argument('--tls',type=bool,default=False,help='whether to use a TLS connection to the server')
parser.add_argument('--input',type=argparse.FileType('r'),help='input file path containing block data',required=True)
parser.add_argument('--ring',type=argparse.FileType('x'),help='ring file path (for safety, cannot already exist)',required=True)
parser.add_argument('--output',type=argparse.FileType('x'),help='output file path (for safety, cannot already exist)',required=True)
parser.add_argument('--status',type=int,default=0,help='how often (in transaction inputs) to output status (0 to disable)')
args = parser.parse_args()

# Input sanity checks
if args.port < 0 or args.port > 65535:
    raise ValueError('Invalid port number!')
if args.status < 0:
    raise ValueError('Invalid status frequency!')

session = requests.Session()
height = 0
counter = 0

# Process each transaction
for transaction in args.input:
    transaction = transaction.strip().split(' ')

    # Status update
    if height != transaction[1]:
        height = transaction[1]
        if args.status > 0 and counter % args.status == 0:
            counter = 0
            print('Processing block',height)
        counter += 1

    result = session.get('{}://{}:{}/api/transaction/{}'.format('https' if args.tls else 'http',args.server,args.port,transaction[3])).json()['data']

    # Parse ring data (if not coinbase)
    if not result['coinbase']:
        for index,ring in enumerate(result['inputs']):
            print(transaction[0],index,' '.join([mixin['public_key'] for mixin in ring['mixins']]),file=args.ring)

    # Parse output data
    if result['outputs']:
        print(transaction[0],' '.join([output['public_key'] for output in result['outputs']]),file=args.output)

