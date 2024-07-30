import hashlib
import logging
import util
from Crypto.Util.number import bytes_to_long, long_to_bytes

class ProxyObliviousTransfer:

    def __init__(self, socket1: util.Socket, socket2: util.Socket, enabled=True, group=None):
        self.socket1 = socket1
        self.socket2 = socket2
        """
        For the Proxy, the first socket is the one connected to the Chooser and the second one is connected to the Sender.
        For the Chooser, the first socket is the one connected to the Proxy and the second one is connected to the Sender.
        For the Sender, the first socket is the one connected to the Proxy and the second one is connected to the Chooser.
        """
        self.enabled = enabled
        self.group = group

    def send_choice(self, bidder_id, choice: list):
        """Chooser sends its choice to the Sender and Proxy.

        Args:
            bidder_id: The ID of the bidder.
            choice: The list of choices to send.
        """

        # Send bidder ID to Sender and Proxy
        logging.debug(f"Send bidder ID {bidder_id} to Sender and Proxy")
        self.socket1.send(bidder_id)
        self.socket1.receive()
        # Prime Group received from the Sender
        self.socket2.send(bidder_id)
        self.group = self.socket2.receive()
        logging.debug("Received group to use for Proxy OT")

        for index in range(len(choice)):
            logging.debug(f"Send wire ID {index + bidder_id * len(choice)} to Sender")
            self.socket2.send(index + bidder_id * len(choice))

            if self.enabled:
                self.pot_chooser(choice[index])

    def pot_chooser(self, b):
        """Proxy Oblivious transfer, Chooser's side.

        Args:
            b: Chooser's input bit used to select one of Sender's messages.
        """
        logging.debug("Proxy OT protocol started")
        G = self.group

        # OT protocol based on Nigel Smart's "Cryptography Made Simple"
        c = self.socket2.receive()
        r = G.rand_int()  
        self.socket1.send(r)
        self.socket1.receive()
        GR = G.gen_pow(r)
        h = (GR, G.mul(c, G.inv(GR)))
        self.socket2.send(h[b])
        self.socket2.receive()

        logging.debug("Proxy OT protocol ended")
    
    def send_msg(self, nbits, wires: list):
        """Sender sends messages to the Proxy."""
        logging.debug("Generating prime group to use for Proxy OT")
        self.group = self.enabled and (self.group or util.PrimeGroup())
        logging.debug("Sending prime group")
        self.socket1.send(self.group)
        self.socket1.receive()

        bidder_id = self.socket2.receive()
        self.socket2.send(self.group)
        

        for _ in range(nbits):
            # receive wire_id from chooser
            wire_id = self.socket2.receive()
            originmsg = [long_to_bytes(wires[wire_id]._get_garbled(0)), long_to_bytes(wires[wire_id]._get_garbled(1))]
            msg = []
            for k in range(2):
                error_detect = hashlib.sha256(originmsg[k]).digest()
                msg.append(error_detect + originmsg[k])
            pair = tuple(msg)
            
            if self.enabled:
                self.pot_sender(pair)

    def pot_sender(self, msgs):
        """Proxy Oblivious transfer, Sender's side.

        Args:
            msgs: A pair (msg1, msg2) to suggest to Proxy.
        """
        logging.debug("Proxy OT protocol started")
        G = self.group

        # OT protocol based on Nigel Smart's "Cryptography Made Simple"
        c = G.gen_pow(G.rand_int())
        self.socket2.send(c)

        PK0 = self.socket2.receive()
        self.socket2.send(True)
        PK1 = G.mul(c, G.inv(PK0))
        k = G.rand_int()
        GK = G.gen_pow(k)
        e0 = util.xor_bytes(msgs[0], self.ot_hash(G.pow(PK0, k), len(msgs[0])))
        e1 = util.xor_bytes(msgs[1], self.ot_hash(G.pow(PK1, k), len(msgs[1])))

        self.socket1.send((GK, e0, e1))
        self.socket1.receive()
        logging.debug("Proxy OT protocol ended")

    def recv_msg(self, nbits, inputs: dict):
        """Proxy receives messages from the Sender."""
        bidder_id = self.socket1.receive()
        logging.debug(f"Receive bidder ID {bidder_id}")
        self.socket1.send(True)
        self.group = self.socket2.receive()
        self.socket2.send(True)

        for i in range(nbits):
            index = bidder_id * nbits + i
            msg = self.pot_proxy()
            if msg is None:
                assert(False == True)
            inputs[index] = msg

    def pot_proxy(self):
        """Proxy Oblivious transfer, Proxy's side. 

        Returns:
            The message selected by Chooser.
        """
        logging.debug("Proxy OT protocol started")

        G = self.group

        # OT protocol based on Nigel Smart's "Cryptography Made Simple"
        r = self.socket1.receive() # proxy receive private key from chooser
        self.socket1.send(True)
        GK, e0, e1 = self.socket2.receive() # proxy receive decrypt key and messages from sender
        self.socket2.send(True)
        e = (e0, e1)
        ot_hash = [self.ot_hash(G.pow(GK, r), len(e[0])), self.ot_hash(G.pow(GK, r), len(e[1]))]
        msg = [util.xor_bytes(e[0], ot_hash[0]), util.xor_bytes(e[1], ot_hash[1])]
        denial_flag = True
        for k in range(2):
            error_detect = msg[k][:32]
            originmsg = msg[k][32:]
            if error_detect == hashlib.sha256(originmsg).digest():
                denial_flag = False
                originmsg = bytes_to_long(originmsg)
                break
        if denial_flag:
            logging.error("Error detected in Proxy OT protocol")
            return None
        logging.debug("Proxy OT protocol ended")
        return originmsg
    

    @staticmethod
    def ot_hash(pub_key, msg_length):
        """Hash function for OT keys."""
        key_length = (pub_key.bit_length() + 7) // 8  # key length in bytes
        bytes = pub_key.to_bytes(key_length, byteorder="big")
        return hashlib.shake_256(bytes).digest(msg_length)
    