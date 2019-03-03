# Perform a set analysis using clusters to identify some spent notes
# Based on: http://fc19.ifca.ai/preproceedings/69-preproceedings.pdf

import unittest
import random

# Remove all instances of given notes from all rings
# IN: list of notes to remove, list of rings
# OUT: whether any notes were removed
# Note: the clip happens in place
def clip(prunes,rings):
    flag = False # were any notes removed?

    for ring in rings:
        for prune in prunes:
            if prune in ring:
                ring.remove(prune)
                flag = True

    # remove empty rings
    rings[:] = [ring for ring in rings if ring != []]

    return flag
        
# Perform a chain reaction, removing 1-rings iteratively
# IN: list of rings
# OUT: (none)
# Note: the removal happens in place
def reaction(rings):
    done = False

    while not done:
        done = True
        prunes = [] # notes that need to be pruned

        # find 1-rings
        for ring in rings:
            if len(ring) == 1:
                done = False
                prunes.append(ring[0])

        # prune all rings
        clip(prunes,rings)

# Find the number of notes contained in a ring but not a cluster of notes
# IN: ring, list of notes
# OUT: number of notes
def distance(ring,pile):
    count = 0
    for note in ring:
        if note not in pile:
            count += 1

    return count

# Find a distance-1 cluster for a given ring
# IN: starting ring, list of rings
# OUT: number of rings in the cluster, set of notes in the cluster
def cluster(seed,rings):
    size = 0 # number of rings in the pile so far
    pile = [] # cluster of notes so far
    pile.extend(seed)

    for ring in rings:
        # find the distance from the ring to the current cluster
        if distance(ring,pile) <= 1:
            size += 1
            pile.extend([note for note in ring if note not in pile])

    return size,pile

# Perform a set analysis and remove spent notes
# IN: set of rings
# OUT: (none)
# Note: the removal happens in place
def sets(rings):
    done = False

    while not done:
        done = True

        for ring in rings:
            size,pile = cluster(ring,rings)
            if size < len(pile):
                continue
            elif size == len(pile): # this is a spent cluster
                done = not clip(pile,rings) # if we removed anything, we're not done
            else: # this would imply a double spend
                raise Exception('Bad ring set!')

# Test the process using some rings
# Note: each ring is a list of characters
# Note: each character is a note
class Test(unittest.TestCase):
    # Test a malformed set of rings
    def test_malformed(self):
        rings = []
        rings.append(list('abc'))
        rings.append(list('bcd'))
        rings.append(list('acd'))
        rings.append(list('abcd'))
        rings.append(list('abd'))

        with self.assertRaises(Exception):
            reaction(rings)
            sets(rings)

    # Test a simple example
    def test_1(self):
        rings = []
        rings.append(list('abcd'))
        rings.append(list('bc'))
        rings.append(list('a'))
        rings.append(list('d'))

        reaction(rings)
        self.assertEqual(rings,[list('bc'),list('bc')])
        sets(rings)
        self.assertEqual(len(rings),0)

    # Test a more complex example
    def test_2(self):
        rings = []
        rings.append(list('a'))
        rings.append(list('bc'))
        rings.append(list('d'))
        rings.append(list('db'))

        rings.append(list('efg'))
        rings.append(list('fgh'))
        rings.append(list('efh'))
        rings.append(list('egh'))

        rings.append(list('ij'))
        rings.append(list('kl'))
        rings.append(list('ijkl'))
        rings.append(list('jkl'))

        reaction(rings)
        self.assertEqual(len(rings),8)
        sets(rings)
        self.assertEqual(len(rings),0)

    # Test duplicate rins
    def test_duplicate(self):
        rings = []
        rings.append(list('abcde'))
        rings.append(list('abcde'))
        rings.append(list('abcde'))
        rings.append(list('abcde'))
        rings.append(list('abcde'))

        reaction(rings)
        sets(rings)
        self.assertEqual(len(rings),0)

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(Test))
