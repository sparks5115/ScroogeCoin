import binascii
# import base58
import hashlib
import json
from fastecdsa import ecdsa, keys, curve, point

class ScroogeCoin(object):
    def __init__(self):
        self.private_key, self.public_key = createKeyPair()
        print("Private Key: ", self.private_key)
        print("Public Key: ", self.public_key)
        
        self.address = createAddress(self.public_key)
        self.chain = [] # list of all the blocks
        self.current_transactions = [] # list of all the current transactions

    def create_coins(self, receivers: dict):
        """
        Scrooge adds value to some coins
        :param receivers: {account:amount, account:amount, ...}
        """

        tx = {
            "sender" : -1, # TODO is this correct?
            # coins that are created do not come from anywhere
            "location": {"block": -1, "tx": -1}, 
            "receivers" : receivers,
        }
        tx["hash"] = self.hash(tx)
        tx["signature"] = self.sign(tx["hash"])

        self.current_transactions.append(tx)

    def hash(self, blob):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # use json.dumps().encode() and specify the corrent parameters
        # use hashlib to hash the output of json.dumps()
        dump = json.dumps(blob, sort_keys=True)
        return hashlib.sha256(dump.encode('utf-8')).hexdigest()

    def sign(self, hash_):
        return ecdsa.sign(hash_, self.private_key, curve.secp256k1)

    def get_user_tx_positions(self, address):
        """
        Scrooge adds value to some coins
        :param address: User.address
        :return: list of all transactions where address is funded
        [{"block":block_num, "tx":tx_num, "amount":amount}, ...]
        """
        funded_transactions = []

        for block in self.chain:
            tx_index = 0
            for old_tx in block["transactions"]:
                for funded, amount in old_tx["receivers"].items():
                    if(address == funded):
                        funded_transactions.append({"block":block["index"], "tx":tx_index, "amount":amount})
                tx_index += 1

        return funded_transactions

    def validate_tx(self, tx, public_key):
        """
        validates a single transaction

        :param tx = {
            "sender" : User.address,
                ## a list of locations of previous transactions
                ## look at
            "locations" : [{"block":block_num, "tx":tx_num, "amount":amount}, ...],
            "receivers" : {account:amount, account:amount, ...}
        }

        :param public_key: User.public_key

        :return: if tx is valid return tx
        """
        is_correct_hash = tx["hash"] == self.hash(tx) #TODO hash of just some parts?
        is_signed = ecdsa.verify(tx["signature"], tx["hash"], public_key, curve.secp256k1)
        is_funded = True # TODO
        is_all_spent = True #TODO
        consumed_previous = True #TODO

        if (is_correct_hash and is_signed and is_funded and is_all_spent and not consumed_previous):
            return True
        else:
            print("Transaction is invalid")
            print("is_correct_hash: ", is_correct_hash)
            print("is_signed: ", is_signed)
            print("is_funded: ", is_funded)
            print("is_all_spent: ", is_all_spent)
            print("consumed_previous: ", consumed_previous)
            return False


    def mine(self):
        """
        mines a new block onto the chain
        """

        block = {
            'previous_hash': hash(self.chain[-1] if len(self.chain)>0 else 0),
            'index': len(self.chain),
            'transactions': self.current_transactions,
        }
        # hash and sign the block
        block["hash"] = self.hash(block)
        block["signature"] = self.sign(block["hash"])

        return block

    def add_tx(self, tx, public_key):
        """
        checks that tx is valid
        adds tx to current_transactions

        :param tx = {
            "sender" : User.address,
                ## a list of locations of previous transactions
                ## look at
            "locations" : [{"block":block_num, "tx":tx_num, "amount":amount}, ...],
            "receivers" : {account:amount, account:amount, ...}
        }

        :param public_key: User.public_key

        :return: True if the tx is added to current_transactions
        """
        if(self.validate_tx(tx, public_key)):
            self.current_transactions.append(tx)
            return True
        else:
            return False

    def show_user_balance(self, address):
        """
        prints balance of address
        :param address: User.address
        """

    def show_block(self, block_num):
        """
        prints out a single formated block
        :param block_num: index of the block to be printed
        """

class User(object):
    def __init__(self, Scrooge):
        self.private_key, self.public_key = createKeyPair()
        self.address = createAddress(self.public_key)

    def hash(self, blob):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        :return: the hash of the blob
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # use json.dumps().encode() and specify the corrent parameters
        # use hashlib to hash the output of json.dumps()
        return hashlib.sha256(json.dumps(blob, sort_keys=True, skipkeys=True).encode()).hexdigest()

    def sign(self, hash_):
        return ecdsa.sign(hash_, self.private_key, curve.secp256k1)
    
    def send_tx(self, receivers, previous_tx_locations):
        """
        creates a TX to be sent
        :param receivers: {account:amount, account:amount, ...}
        :param previous_tx_locations
        """

        tx = {
                "sender" : self.address,
                "locations" : previous_tx_locations,
                "receivers" : receivers
            }

        tx["hash"] = self.hash(tx)
        tx["signature"] = self.sign(tx["hash"])

        return tx
    
def createKeyPair():
    return keys.gen_keypair(curve.secp256k1) #THIS IS CORRECT


    
def createAddress(ecdsaPublicKey):
    return hashlib.sha256(hex(ecdsaPublicKey.x << 256 | ecdsaPublicKey.y).encode()).hexdigest() #THIS IS CORRECT


def main():

    # dict - defined using {key:value, key:value, ...} or dict[key] = value
        # they are used in this code for blocks, transactions, and receivers
        # can be interated through using dict.items()
        # https://docs.python.org/3/tutorial/datastructures.html#dictionaries

    # lists -defined using [item, item, item] or list.append(item) as well as other ways
        # used to hold lists of blocks aka the blockchain
        # https://docs.python.org/3/tutorial/datastructures.html#more-on-lists

    # fastecdsa - https://pypi.org/project/fastecdsa/
    # hashlib - https://docs.python.org/3/library/hashlib.html
    # json - https://docs.python.org/3/library/json.html

    # Example of how the code will be run
    Scrooge = ScroogeCoin()
    users = [User(Scrooge) for i in range(10)]
    Scrooge.create_coins({users[0].address:10, users[1].address:20, users[3].address:50})
    Scrooge.mine()

    user_0_tx_locations = Scrooge.get_user_tx_positions(users[0].address)
    first_tx = users[0].send_tx({users[1].address: 2, users[0].address:8}, user_0_tx_locations)
    Scrooge.add_tx(first_tx, users[0].public_key)
    Scrooge.mine()

    second_tx = users[1].send_tx({users[0].address:20}, Scrooge.get_user_tx_positions(users[1].address))
    Scrooge.add_tx(second_tx, users[1].public_key)
    Scrooge.mine()

    Scrooge.get_user_tx_positions(users[1].address)
    Scrooge.get_user_tx_positions(users[0].address)

    Scrooge.show_user_balance(users[0].address)


if __name__ == '__main__':
   main()
