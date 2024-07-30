import util
import logging
import circuit
import pickle
import pot
import random
import util

Proxy_Chooser_PORT = 5555
Chooser_Sender_PORT = 5556
Sender_Proxy_PORT = 5557

mbidders = 8
nbits = 8

def int2nbitlist(num, nbits):
    num = bin(num)[2:].zfill(nbits)[::-1]
    return [int(x) for x in num]

class Proxy:
    def __init__(self, PC_PORT, PS_PORT, mbidders, nbits, OTenabled=True, group=None):
        self.socketC = util.CilentSocket(PC_PORT)
        self.socketS = util.CilentSocket(PS_PORT)
        self.mbidder = mbidders
        self.nbits = nbits
        self.OTenabled = OTenabled
        self.group = group
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketC, self.socketS, self.OTenabled, self.group)
        self.inputs = {}
        self.gates = {}
        self.wire_indexes = []
        self.wires = {}

    def listen(self):
        self.circuit, self.wire_indexes, self.wires, self.gates = self.recv_circuit()
        
        self.socketS.send(True)

        for _ in range(self.mbidder):
            self.ProxyOT.recv_msg(self.nbits, self.inputs)
        
        for index, msg in self.inputs.items():
            print(f"Wire {index} received message {msg}")

        self.socketS.receive()
        self.socketS.send(self.inputs)

        circuit.gates = self.gates
        answer = self.circuit.evaluate(self.inputs)
        
        print("Highest bidder:", end=" ")
        for i in range(mbidders):
            if self.wires[self.wire_indexes[i]]._de_garbled(answer[self.wire_indexes[i]]) == 0:
                print(f"Bidder {i}", end=" ")
        price = 0
        for i in range(nbits):
            price += self.wires[self.wire_indexes[i + mbidders]]._de_garbled(answer[self.wire_indexes[i + mbidders]]) << i
        print(f"\n2nd highest price: {price}")

    def recv_circuit(self):
        return pickle.loads(self.socketS.receive())

class Chooser:
    def __init__(self, PC_PORT, CS_PORT, bid, bidder_id, OTenabled=True, group=None):
        self.socketP = util.ServerSocket(PC_PORT)
        self.socketS = util.ServerSocket(CS_PORT)
        self.OTenabled = OTenabled
        self.group = group
        self.bidlist = int2nbitlist(bid, nbits)
        self.bidder_id = bidder_id
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketP, self.socketS, self.OTenabled, self.group)
        print(self.bidlist)

class Sender:
    def __init__(self, PS_PORT, CS_PORT, mbidders, nbits, OTenabled=True, group=None):
        self.socketP = util.ServerSocket(PS_PORT)
        self.socketC = util.CilentSocket(CS_PORT)
        self.mbidders = mbidders
        self.nbits = nbits
        self.OTenabled = OTenabled
        self.group = group
        self.bids = []
        for _ in range(self.mbidders):
            tmp = []
            for _ in range(self.nbits):
                w = circuit.wire()
                tmp.append(w.get_index())
            self.bids.append(tmp)
        self.circuit = circuit.max2ndm_nbit(self.nbits, self.bids)
        logging.debug(f"{len(circuit.wires)} wires and {len(circuit.gates)} gates generated.")
        logging.debug(f"Object packed in {len(pickle.dumps([self.circuit, circuit.gates]))} bytes")
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketP, self.socketC, self.OTenabled, self.group)

    def listen(self):
        self.send_circuit()  

        for _ in range(self.mbidders):
            self.ProxyOT.send_msg(self.nbits, circuit.wires)

        for i in range(64):
            print(f"Wire {i}: {circuit.wires[i].value_table}")

        self.socketP.send(True)
        inputs = self.socketP.receive()

        answer = self.circuit.evaluate(inputs)
        print("Highest bidder:", end=" ")
        for i in range(self.mbidders):
            if circuit.wires[self.circuit.outputs[i]]._de_garbled(answer[self.circuit.outputs[i]]) == 0:
                print(f"Bidder {i}", end=" ")
        price = 0
        for i in range(nbits):
            price += circuit.wires[self.circuit.outputs[i+self.mbidders]]._de_garbled(answer[self.circuit.outputs[i+self.mbidders]]) << i
        print(f"\n2nd highest price: {price}")

    def send_circuit(self):
        output_index = self.circuit.get_outputs()
        outputs = {}
        for i in range(len(output_index)):
            outputs[output_index[i]] = circuit.wires[output_index[i]]
        dump = pickle.dumps((self.circuit, output_index, outputs, circuit.gates))
        self.socketP.send(dump)
        self.socketP.receive()


def main(
    party,
    # oblivious_transfer=True,
    loglevel=logging.WARNING,
):
    logging.getLogger().setLevel(loglevel)

    if party == "sender":
        sender = Sender(Sender_Proxy_PORT, Chooser_Sender_PORT, mbidders, nbits)
        sender.listen()
    elif party == "chooser":
        bids = []
        for _ in range(mbidders):
            bids.append(random.getrandbits(nbits))

        print(f"bids: {bids}")

        for i in range(mbidders):
            chooser = Chooser(Proxy_Chooser_PORT, Chooser_Sender_PORT, bids[i], i)
            chooser.ProxyOT.send_choice(chooser.bidder_id, chooser.bidlist)

    elif party == "proxy":
        proxy = Proxy(Proxy_Chooser_PORT, Sender_Proxy_PORT, mbidders, nbits)
        proxy.listen()
    
    else:
        logging.error(f"Unknown party '{party}'")

if __name__ == '__main__':
    import argparse

    def init():
        loglevels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["sender", "chooser", "proxy"],
                            help="the proxy OT party to run")
        # parser.add_argument("--no-oblivious-transfer",
        #                     action="store_true",
        #                     help="disable oblivious transfer")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            party=parser.parse_args().party,
            # oblivious_transfer=not parser.parse_args().no_oblivious_transfer,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()
