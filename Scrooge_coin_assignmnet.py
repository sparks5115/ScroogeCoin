import hashlib
import json
from fastecdsa import ecdsa, keys, curve, point

class ScroogeCoin(object):
    def __init__(self):
        self.private_key, self.public_key = # MUST USE secp256k1 curve from fastecdsa
        self.address = # create the address using public key, and bitwise operation, may need hex(value).hexdigest()
        self.chain = [] # list of all the blocks
        self.current_transactions = [] # list of all the current transactions

    def create_coins(self, receivers: dict):
        """
        Scrooge adds value to some coins
        :param receivers: {account:amount, account:amount, ...}
        """

        tx = {
            "sender" : # address,
            # coins that are created do not come from anywhere
            "location": {"block": -1, "tx": -1},
            "receivers" : receivers,
        }
        tx["hash"] = # hash of tx
        tx["signature"] = # signed hash of tx

        self.current_transactions.append(tx)

    def hash(self, blob):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # use json.dumps().encode() and specify the corrent parameters
        # use hashlib to hash the output of json.dumps()
        return # hash_of_blob

    def sign(self, hash_):
        return # use fastecdsa library

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
        is_correct_hash = False
        is_signed = False
        is_funded = False
        is_all_spent = False
        consumed_previous = False

        if (is_correct_hash and is_signed and is_funded and is_all_spent and not consumed_previous):
            return tx


    def mine(self):
        """
        mines a new block onto the chain
        """

        block = {
            'previous_hash': # previous_hash,
            'index': # index,
            'transactions': # transactions,
        }
        # hash and sign the block
        tx["hash"] = # hash of block
        tx["signature"] = # signed hash of block

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
        self.private_key, self.public_key = # MUST USE secp256k1 curve from fastecdsa
        self.address = # create the address using public key, and bitwise operation, may need hex(value).hexdigest()

    def hash(self, blob):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        :return: the hash of the blob
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # use json.dumps().encode() and specify the corrent parameters
        # use hashlib to hash the output of json.dumps()
        return # hash_of_blob

    def sign(self, hash_):
        return # use fastecdsa library

    def send_tx(self, receivers, previous_tx_locations):
        """
        creates a TX to be sent
        :param receivers: {account:amount, account:amount, ...}
        :param previous_tx_locations
        """

        tx = {
                "sender" : # address,
                "locations" : previous_tx_locations,
                "receivers" : receivers
            }

        tx["hash"] = # hash of TX
        tx["signature"] = # signed hash of TX

        return tx

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
