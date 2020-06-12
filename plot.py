from sys import version_info

if version_info[0] != 3:
    raise Exception('This tool requires Python 3!')

import requests
import argparse

parser = argparse.ArgumentParser(description='Compute a distribution of transactions by month, classified by type')
parser.add_argument('--server',help='server IP or domain',required=True)
parser.add_argument('--port',type=int,default=8081,help='listening port on the server')
parser.add_argument('--tls',type=bool,default=False,help='whether to use a TLS connection to the server')
parser.add_argument('--file_transactions',type=argparse.FileType('r'),help='input file path containing transaction data',required=True)
parser.add_argument('--file_plot',type=argparse.FileType('x'),help='output file path for plot data',required=True)
parser.add_argument('--precision',type=int,default=1000,help='precision for month estimation')
args = parser.parse_args()

# Fetch month data (we offset the genesis block due to a bad timestamp)
print('Fetching timestamp data...')
session = requests.Session()
mapped = {} # { height: [year, month] }
try:
    end_height = session.get('{}://{}:{}/api/networkinfo'.format('https' if args.tls else 'http',args.server,args.port)).json()['data']['height']
except:
    raise Exception('Server did not respond. Not a big deal; just run the tool again.')

for block in range(0,end_height,args.precision):
    timestamp = session.get('{}://{}:{}/api/block/{}'.format('https' if args.tls else 'http',args.server,args.port,block if block != 0 else 1)).json()['data']['timestamp_utc'].split('-')
    mapped[block] = [timestamp[0],timestamp[1]]

# Compute the month crossover points
current_month = mapped[0]
crossovers = {}
for block in sorted(mapped.keys()):
    if mapped[block] != current_month:
        current_month = mapped[block]
        crossovers[block] = '{}-{}'.format(mapped[block][0],mapped[block][1])

distribution = {}
index = 1
current_crossover = sorted(crossovers.keys())[0]
next_crossover = sorted(crossovers.keys())[index]
current_month = crossovers[current_crossover]
distribution[current_month] = [0,0,0,0] # transaction types (coinbase,clear,semi,opaque)

# Process all transactions
print('Processing transactions...')
for tx in args.file_transactions:
    tx = tx.strip().split(' ')
    block = int(tx[1])
    if next_crossover is None or block < next_crossover:
        distribution[current_month][int(tx[2])] += 1
    else:
        index += 1
        current_crossover = next_crossover
        try:
            next_crossover = sorted(crossovers.keys())[index]
        except:
            next_crossover = None # there is no next month
        current_month = crossovers[current_crossover]
        distribution[current_month] = [0,0,0,0]

for key in sorted(distribution.keys()):
    print(key,distribution[key][1],distribution[key][2],distribution[key][3],file=args.file_plot)
