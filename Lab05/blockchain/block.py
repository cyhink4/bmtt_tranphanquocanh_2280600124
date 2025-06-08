import hashlib
import time


class Block:
    def __init__(self,index,previous_hash,timestamp, transactions,proof):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.proof = proof
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.proof}"
        return hashlib.sha256(data.encode()).hexdigest()
