# Transcript challenge handling

from dumb25519 import *

class Transcript:
    # Initialize the transcript
    def __init__(self,prefix):
        self.state = hash_to_scalar(prefix)

    # Update the transcript with public data
    def update(self,data=None):
        if data is None:
            self.state = hash_to_scalar(self.state)
        else:
            self.state = hash_to_scalar(self.state,data)

    # Retrieve a challenge scalar and update the state
    def challenge(self):
        x = self.state
        self.update() # ensures fresh challenges
        return x
