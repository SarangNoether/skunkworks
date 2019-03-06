# Simulate a maximal block size attack on the Monero network
from sys import argv

MEDIAN_WINDOW = 100 # number of recent blocks for median computation
MAX_MULTIPLIER = 2.0 # how many times the median can the block size be?
MEDIAN_THRESHOLD = 300*1000 # initial maximal value for median (scaled kB -> B)
try:
    ATTACK_HOURS = int(argv[1]) # number of hours to run the attack
except:
    ATTACK_HOURS = 24
BLOCK_TIME = 2 # block addition time (minutes)
REWARD = 3.5 # block reward (XMR)
BASE_FEE = 0.0004 # base dynamic fee/kB
MAX_BLOCK = 500*1000*1000 # hard cap on block size (B)

window = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW # size of recent blocks (B), with index -1 most recent
blockchain = 0 # total change in blockchain size (B)
cost = 0 # cost of attack (XMR)

# Compute the median of a list
def get_median(vec):
    temp = sorted(vec)
    if len(temp) % 2 == 1:
        return temp[len(temp)/2]
    else:
        return int((temp[len(temp)/2]+temp[len(temp)/2-1])/2)

# Run the attack
print 'running attack for',ATTACK_HOURS,'hours'
for block in range(ATTACK_HOURS*60/BLOCK_TIME):
    median = get_median(window)
    window = window[1:]
    window.append(min(median*MAX_MULTIPLIER,MAX_BLOCK))
    blockchain += window[-1]

    penalty = REWARD*(float(window[-1])/median-1)**2
    actual_reward = REWARD-penalty
    min_fee_per_kb = BASE_FEE*(float(MEDIAN_THRESHOLD)/median)*(float(actual_reward)/10)
    cost += max(penalty,min_fee_per_kb*window[-1])

print 'block size at end of attack (MB):',window[-1]/1000/1000
print 'blockchain increase at end of attack (MB):',blockchain/1000/1000
print 'total attack cost (XMR):',cost
