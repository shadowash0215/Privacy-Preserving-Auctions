import util
import logging
import circuit
import pickle
import pot
import random
import util

logger = logging.getLogger(__name__)

Proxy_Chooser_PORT = 5555
Chooser_Sender_PORT = 5556
Sender_Proxy_PORT = 5557

mbidders = 8
nbits = 8

class Proxy:
    def __init__(self, PC_PORT, PS_PORT):
        self.socketC = util.CilentSocket(PC_PORT)
        self.socketS = util.CilentSocket(PS_PORT)
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketC, self.socketS)
        self.inputs = {}
        self.wire_indexes = []
        self.wires = {}

    def listen(self):
        self.circuit, self.wires, circuit.gates = self.recv_circuit()
        self.wire_indexes = sorted(self.wires)

        self.socketS.send(True)

        for _ in range(mbidders):
            self.ProxyOT.recv_msg(nbits, self.inputs)
        
        for index, msg in self.inputs.items():
            logging.debug(f"Received message {msg} for wire {index}")

        if logger.isEnabledFor(logging.DEBUG):
            self.socketS.receive()
            self.socketS.send(self.inputs)

        answer = self.circuit.evaluate(self.inputs)
        
        self.output_results(answer)

    def recv_circuit(self):
        return pickle.loads(self.socketS.receive())
    
    def output_results(self, answer):
        print("Highest bidder:", end=" ")
        for i in range(mbidders):
            if self.wires[self.wire_indexes[i]]._de_garbled(answer[self.wire_indexes[i]]) == 0:
                print(f"Bidder {i}", end=" ")
        price = 0
        for i in range(nbits):
            price += self.wires[self.wire_indexes[i + mbidders]]._de_garbled(answer[self.wire_indexes[i + mbidders]]) << i
        print(f"\n2nd highest price: {price}")

class Chooser:
    def __init__(self, PC_PORT, CS_PORT, bid, bidder_id):
        self.socketP = util.ServerSocket(PC_PORT)
        self.socketS = util.ServerSocket(CS_PORT)
        self.bidlist = util.int2nbitlist(bid, nbits)
        self.bidder_id = bidder_id
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketP, self.socketS)
        logging.debug(f"Bidder {bidder_id}: {self.bidlist}")

class Sender:
    def __init__(self, PS_PORT, CS_PORT):
        self.socketP = util.ServerSocket(PS_PORT)
        self.socketC = util.CilentSocket(CS_PORT)
        self.bids = []
        for _ in range(mbidders):
            tmp = []
            for _ in range(nbits):
                w = circuit.wire()
                tmp.append(w.get_index())
            self.bids.append(tmp)
        self.circuit = circuit.max2ndm_nbit(nbits, self.bids)
        logging.info(f"{len(circuit.wires)} wires and {len(circuit.gates)} gates generated.")
        self.ProxyOT = pot.ProxyObliviousTransfer(self.socketP, self.socketC)

    def listen(self):
        self.send_circuit()  

        for _ in range(mbidders):
            self.ProxyOT.send_msg(nbits, circuit.wires)

        if logger.isEnabledFor(logging.DEBUG):
            for i in range(nbits * mbidders):
                logging.debug(f"Wire {i}: {circuit.wires[i].value_table}")
            self.socketP.send(True)
            inputs = self.socketP.receive()

            answer = self.circuit.evaluate(inputs)
            print("Highest bidder:", end=" ")
            for i in range(mbidders):
                if circuit.wires[self.circuit.outputs[i]]._de_garbled(answer[self.circuit.outputs[i]]) == 0:
                    print(f"Bidder {i}", end=" ")
            price = 0
            for i in range(nbits):
                price += circuit.wires[self.circuit.outputs[i + mbidders]]._de_garbled(answer[self.circuit.outputs[i + mbidders]]) << i
            print(f"\n2nd highest price: {price}")

    def send_circuit(self):
        output_index = self.circuit.get_outputs()
        outputs = {}
        for i in range(len(output_index)):
            outputs[output_index[i]] = circuit.wires[output_index[i]]
        dump = pickle.dumps((self.circuit, outputs, circuit.gates))
        logging.info(f"Object packed in {len(dump)} bytes")
        self.socketP.send(dump)
        self.socketP.receive()


def main(
    party,
    loglevel=logging.WARNING,
):
    logging.getLogger().setLevel(loglevel)

    if party == "sender":
        sender = Sender(Sender_Proxy_PORT, Chooser_Sender_PORT)
        sender.listen()
    elif party == "chooser":
        bids = []
        for _ in range(mbidders):
            bids.append(random.getrandbits(nbits))

        logging.info(f"bids: {bids}")

        for i in range(mbidders):
            chooser = Chooser(Proxy_Chooser_PORT, Chooser_Sender_PORT, bids[i], i)
            chooser.ProxyOT.send_choice(chooser.bidder_id, chooser.bidlist)

    elif party == "proxy":
        proxy = Proxy(Proxy_Chooser_PORT, Sender_Proxy_PORT)
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

        parser = argparse.ArgumentParser(description="Run Proxy OT protocol.")
        parser.add_argument("party",
                            choices=["sender", "chooser", "proxy"],
                            help="the proxy OT party to run")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            party=parser.parse_args().party,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()
