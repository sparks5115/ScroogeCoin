import hashlib
import json
from fastecdsa import ecdsa, keys, curve, point

def consistent_hash(blob):
        return hashlib.sha256(json.dumps(blob, sort_keys=True, skipkeys=True).encode()).hexdigest()

class ScroogeCoin(object):
    def __init__(self):
        self.private_key, self.public_key = createKeyPair()

        self.address = createAddress(self.public_key)
        self.chain = []  # list of all the blocks
        self.current_transactions = []  # list of all the current transactions
        self.users = []

    def create_coins(self, receivers: dict):
        """
        Scrooge adds value to some coins
        :param receivers: {account:amount, account:amount, ...}
        """

        tx = {
            "sender": -1,  # TODO is this correct?
            # coins that are created do not come from anywhere
            "locations": [{"block": -1, "tx": -1}],
            "receivers": receivers,
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
        return consistent_hash(blob)

    def sign(self, hash_):
        return ecdsa.sign(hash_, self.private_key, curve.secp256k1)

    def get_user_tx_positions(self, address):
        """
        :param address: User.address
        :return: list of all transactions where address is funded
        [{"block":block_num, "tx":tx_num, "amount":amount}, ...]
        """
        funded_transactions = []

        for block in self.chain:
            tx_index = 0
            for old_tx in block["transactions"]:
                for funded, amount in old_tx["receivers"].items():
                    if (address == funded):
                        funded_transactions.append(
                            {"block": block["index"], "tx": tx_index, "amount": amount})
                tx_index += 1

        return funded_transactions

    #this decides which transactions to spend. It will simply select the oldest transactions until it has enough coins to spend
    def select_coins_to_spend(self, address, amount):
        """
        :param amount: amount of coins to be selected
        :param address: User.address
        :return: list of locations of transactions that fund the acount
        """
        funded_transactions = self.get_user_tx_positions(address)

        #go through the chain and remove transactions that have been spent
        for block in self.chain:
            for tx in block["transactions"]:
                if (tx["sender"] == address): #if the sender of this transaction is the account we are spending
                    for location in tx["locations"]:
                        for funded_transaction in funded_transactions: 
                            if (funded_transaction["block"] == location["block"] and funded_transaction["tx"] == location["tx"]):
                                funded_transactions.remove(funded_transaction)


        selected_transactions = []
        selected_amount = 0
        for tx in funded_transactions:
            selected_transactions.append(tx)
            selected_amount += tx["amount"]
            if (selected_amount >= amount):
                return selected_transactions

        return None #if we get here, we don't have enough coins to spend


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
        #check that the hash is correct
        if( self.hash({key: tx[key] for key in ['sender', 'locations', 'receivers']}) != tx["hash"]): #we only hash the fields that were hashed when the transaction was created
            error("hashes don't match")
            # print("transaction:")
            # print(tx)
            return False
        
        #check that the signature is correct
        if(not ecdsa.verify(tx["signature"], tx["hash"], public_key, curve.secp256k1)):
            error("invalid signature")
            # print("transaction:")
            # print(tx)
            return False

        #The consumed coins are valid, that is the coins are created in previous transactions
        #check that the transaction outputs are actually on the blockchain
        for location in tx["locations"]:
            #if the location is on the blockchain and the transaction number is valid in this block
            if (location["block"] >= len(self.chain) or location["tx"] >= len(self.chain[location["block"]]["transactions"])):
                error("Transaction not on blockchain")
                # print("transaction:")
                # print(tx)
                return False #this should never happen as Scrooge is the one who decides which transactions to spend in this model
            
            #check that the sender of the transaction receives the amount of coins that they claim come from this transaction
            if (self.chain[location["block"]]["transactions"][location["tx"]]["receivers"][tx["sender"]] != location["amount"]):
                error("invalid UTXO")
                # print("transaction:")
                # print(tx)
                return False #this should never happen as Scrooge is the one who decides which transactions to spend in this model



        #The consumed coins were not already consumed in some previous transaction
        #loop through all transactions after the ones that are being spent
        for location in tx["locations"]:
            for block in self.chain[location["block"]:]:
                for transaction in block['transactions']:
                    if (transaction["sender"] == tx["sender"]): #if the sender of this transaction is the account we are spending
                        for transaction_location in transaction["locations"]:
                            if (transaction_location["block"] == location["block"] and transaction_location["tx"] == location["tx"]):
                                error("double spend")
                                # print("transaction:")
                                # print(tx)
                                return False #this should never happen as Scrooge is the one who decides which transactions to spend in this model
                

        #The total value of the coins that come out of this transaction is equal to the total value of the coins that went in
        value_in = 0
        value_out = 0
        for location in tx["locations"]:
            value_in += location["amount"]
        for receiver, amount in tx["receivers"].items():
            value_out += amount
        if (value_in != value_out):
            error(f"value in({value_in}) != value out({value_out})")
            return False
        
        
        return True #the transaction is valid


    def mine(self):
        """
        mines a new block onto the chain
        """
        block = {
            'previous_hash': self.hash(self.chain[-1] if len(self.chain) > 0 else 0),
            'index': len(self.chain),
            'transactions': self.current_transactions,
        }
        # hash and sign the block
        block["hash"] = self.hash(block)
        block["signature"] = self.sign(block["hash"])

        # reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)

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
        if (self.validate_tx(tx, public_key)):
            self.current_transactions.append(tx)
            return True
        else:
            return False

    def show_user_balance(self, address):
        """
        prints balance of address
        :param address: User.address
        """
        balance = 0
        for block in self.chain:
            for old_tx in block["transactions"]:
                for funded, amount in old_tx["receivers"].items():
                    if (address == funded):
                        balance += amount
                if (old_tx["sender"] == address):
                    for funded, amount in old_tx["receivers"].items():
                        balance -= amount

        print("Balance of ", address, ": ", balance)

    def show_block(self, block_num):
        """
        prints out a single formated block
        :param block_num: index of the block to be printed
        """

        block = self.chain[block_num]

        print("Block ", block_num, ":")
        print("Previous Hash: ", block["previous_hash"])
        print("Hash: ", block["hash"])
        print("Signature: ", block["signature"])
        print("############# START TRANSACTIONS #############")
        for tx in block["transactions"]:
            print("Sender: ", tx["sender"])
            print("Locations: ", tx["locations"])
            print("Receivers: ", tx["receivers"])
            print("Hash: ", tx["hash"])
            print("Signature: ", tx["signature"])
            print("############# END TRANSACTION #############")
    

    def make_transaction(self, sender_index, receiver_index, amount):
        """
        makes a simple transaction from sender to receiver (does not work for multiple receivers or senders, but does send change back to sender)
        :param sender_index: index of the sender in self.users
        :param receiver_index: index of the receiver in self.users
        :param amount: amount of coins to send
        """

        sender = self.users[sender_index]
        receiver = self.users[receiver_index]
        coins_to_spend = self.select_coins_to_spend(sender.address, amount)
        
        if coins_to_spend is not None:
            total_coins = sum([coin['amount'] for coin in coins_to_spend])
            change = total_coins - amount
            tx = sender.send_tx({receiver.address: amount, sender.address: change}, coins_to_spend)
            self.add_tx(tx, sender.public_key)
            print(f"user {sender_index} sent {amount} coins to user {receiver_index} and got {change} coins back\n")
        else:
            error(f"user {sender_index} does not have enough coins to spend\n")

def error(msg):
    print("ERROR: " + msg + "\n")


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
        return consistent_hash(blob)

    def sign(self, hash_):
        return ecdsa.sign(hash_, self.private_key, curve.secp256k1)

    def send_tx(self, receivers, previous_tx_locations):
        """
        creates a TX to be sent
        :param receivers: {account:amount, account:amount, ...}
        :param previous_tx_locations
        """

        tx = {
            "sender": self.address,
            "locations": previous_tx_locations,
            "receivers": receivers
        }

        tx["hash"] = self.hash(tx)
        tx["signature"] = self.sign(tx["hash"])

        return tx


def createKeyPair():
    return keys.gen_keypair(curve.secp256k1)  # THIS IS CORRECT

def createAddress(ecdsaPublicKey):
    # THIS IS CORRECT
    return hashlib.sha256(hex(ecdsaPublicKey.x << 256 | ecdsaPublicKey.y).encode()).hexdigest()

def tests():
    #Mine a valid transaction that consumes coins from a previous block
    Scrooge = ScroogeCoin()
    Scrooge.users = [User(Scrooge) for i in range(10)]
    users = Scrooge.users

    #print the balance of users 0, 1, and 3
    Scrooge.show_user_balance(users[0].address)
    Scrooge.show_user_balance(users[1].address)
    Scrooge.show_user_balance(users[3].address)

    print("Creating coins for users 0, 1, and 3...")
    Scrooge.create_coins(
        {users[0].address: 10, users[1].address: 20, users[3].address: 50})
    Scrooge.mine()

    #print the balance of users 0, 1, and 3 again
    Scrooge.show_user_balance(users[0].address)
    Scrooge.show_user_balance(users[1].address)
    Scrooge.show_user_balance(users[3].address)
    print()

    Scrooge.make_transaction(0, 1, 2)
    Scrooge.mine()

    #print the balance of users 0, 1, and 3 again
    Scrooge.show_user_balance(users[0].address)
    Scrooge.show_user_balance(users[1].address)
    Scrooge.show_user_balance(users[3].address)
    print()

    print("time to cause some trouble \n")

    print("try to send more money than a user has")
    Scrooge.make_transaction(0, 1, 100)
    #this is caught by scrooge and therefore isnt even considered... we will need to go over scrooges head

    print("sending coins that do not exist")
    tx_amount = 2
    coins_to_spend = [{'block': 13, 'tx': 1, 'amount': 12}] #this coin does not exist
    change = sum([i['amount'] for i in coins_to_spend]) - tx_amount
    first_tx = users[0].send_tx(
        {users[1].address: tx_amount, users[0].address: change}, coins_to_spend)
    Scrooge.add_tx(first_tx, users[0].public_key)

    print("note that this will also not work if we say that the user recieved the wrong amount of coins")
    coins_to_spend = [{'block': 0, 'tx': 0, 'amount': 12}] #user 0 only recieves 10 coins here
    change = sum([i['amount'] for i in coins_to_spend]) - tx_amount
    first_tx = users[0].send_tx(
        {users[1].address: tx_amount, users[0].address: change}, coins_to_spend)
    Scrooge.add_tx(first_tx, users[0].public_key)

    print("sending coins that have already been spent")
    tx_amount = 2
    coins_to_spend = [{'block': 0, 'tx': 0, 'amount': 10}] #these coins were already spent in the first transaction
    change = sum([i['amount'] for i in coins_to_spend]) - tx_amount
    first_tx = users[0].send_tx(
        {users[1].address: tx_amount, users[0].address: change}, coins_to_spend)
    Scrooge.add_tx(first_tx, users[0].public_key)

    print("creating coins from a transaction")
    user_0_coins_to_spend = Scrooge.select_coins_to_spend(users[0].address, 2)
    first_tx = users[0].send_tx(
        {users[1].address: tx_amount, users[0].address: 25}, user_0_coins_to_spend)
    Scrooge.add_tx(first_tx, users[0].public_key)


    print("sending coins that have been signed incorrectly")
    tx_amount = 2
    user_0_coins_to_spend = Scrooge.select_coins_to_spend(users[0].address, 2)
    if(user_0_coins_to_spend != None):
        #find the change by subtracting the amount spent from the amount of coins in user_0_coins_to_spend
        user_0_change = sum([i['amount'] for i in user_0_coins_to_spend]) - tx_amount
        first_tx = users[0].send_tx(
            {users[1].address: tx_amount, users[0].address: user_0_change}, user_0_coins_to_spend)
        Scrooge.add_tx(first_tx, users[1].public_key) #this should be users[0].public_key
    else:
        print("user 0 does not have enough coins to send")

    print("sending coins from two transactions (consolidating coins)")
    Scrooge.make_transaction(1, 0, 21)
    Scrooge.mine()

    #print the balance of users 0, 1, and 3 again
    Scrooge.show_user_balance(users[0].address)
    Scrooge.show_user_balance(users[1].address)
    Scrooge.show_user_balance(users[3].address)
    print()

    Scrooge.show_block(2)


if __name__ == '__main__':
    #main()
    tests()