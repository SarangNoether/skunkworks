# Simulate a maximal block attack on the Monero network
# This uses the scheme proposed by ArticMine
from sys import argv

MEDIAN_WINDOW_SMALL = 100 # number of recent blocks for median computation
MEDIAN_WINDOW_BIG = 100000
MULTIPLIER_SMALL = 1.4 # multipliers for determining weights
MULTIPLIER_BIG = 50.0
MEDIAN_THRESHOLD = 300*1000 # initial value for median (scaled kB -> B)
try:
    ATTACK_HOURS = int(argv[1]) # number of hours to run the attack
except:
    ATTACK_HOURS = 24
BLOCK_TIME = 2 # block addition time (minutes)
REWARD = 3.5 # block reward (XMR)
BASE_FEE = 0.0004 # base dynamic fee/kB

weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_SMALL # weights of recent blocks (B), with index -1 most recent
lt_weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_BIG # long-term weights
blockchain = 0 # total change in blockchain size (B)
cost = 0 # cost of attack (XMR)

# Compute the median of a list
def get_median(vec):
    temp = vec
    #temp = sorted(vec)
    if len(temp) % 2 == 1:
        return temp[len(temp)/2]
    else:
        return int((temp[len(temp)/2]+temp[len(temp)/2-1])/2)

# Run the attack
print 'running attack for',ATTACK_HOURS,'hours'
for block in range(ATTACK_HOURS*60/BLOCK_TIME):
    # determine the long-term effective weight
    lt_eff = max(MEDIAN_THRESHOLD,get_median(lt_weights[-MEDIAN_WINDOW_BIG:]))

    # determine the effective weight
    eff = min(max(MEDIAN_THRESHOLD,get_median(weights[-MEDIAN_WINDOW_SMALL:])),MULTIPLIER_BIG*lt_eff)
    
    # drop the lowest values
    weights = weights[1:]
    lt_weights = lt_weights[1:]

    # add a block of max weight
    max_weight = 2.0*eff
    weights.append(max_weight)
    lt_weights.append(min(max_weight,MULTIPLIER_SMALL*lt_eff))
    blockchain += weights[-1]

    # assume the cost precisely offsets the total penalty
    median_small = get_median(weights[-MEDIAN_WINDOW_SMALL:])
    penalty = REWARD*(float(weights[-1])/median_small-1)**2
    actual_reward = REWARD-penalty
    min_fee_per_kb = BASE_FEE*(float(MEDIAN_THRESHOLD)/lt_weights[-1])*(float(actual_reward)/10)
    cost += max(penalty,min_fee_per_kb*weights[-1])

print 'block size at end of attack (MB):',weights[-1]/1000/1000
print 'blockchain increase at end of attack (MB):',blockchain/1000/1000
print 'total attack cost (XMR):',cost
