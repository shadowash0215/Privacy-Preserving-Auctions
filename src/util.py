import operator
import random
from hashlib import sha256
import zmq
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

# SOCKET
SERVER_HOST = "localhost"

class Socket:
    def __init__(self, socket_type):
        self.socket = zmq.Context().socket(socket_type)
        self.poller = zmq.Poller()
        self.poller.register(self.socket, zmq.POLLIN)

    def send(self, msg):
        self.socket.send_pyobj(msg)

    def receive(self):
        return self.socket.recv_pyobj()

    def send_wait(self, msg):
        self.send(msg)
        return self.receive()

    """
    From https://stackoverflow.com/questions/17174001/stop-pyzmq-receiver-by-keyboardinterrupt
    """

    def poll_socket(self, timetick=100):
        try:
            while True:
                obj = dict(self.poller.poll(timetick))
                if self.socket in obj and obj[self.socket] == zmq.POLLIN:
                    yield self.socket.recv_pyobj()
        except KeyboardInterrupt:
            pass

class CilentSocket(Socket):
    def __init__(self, CILENT_PORT):
        endpoint=f"tcp://*:{CILENT_PORT}"
        super().__init__(zmq.REP)
        self.socket.bind(endpoint)


class ServerSocket(Socket):
    def __init__(self, SERVER_PORT):
        endpoint=f"tcp://{SERVER_HOST}:{SERVER_PORT}"
        super().__init__(zmq.REQ)
        self.socket.connect(endpoint)

# PRIME GROUP
PRIME_BITS = 512  # order of magnitude of prime in base 2

def xor_bytes(seq1, seq2):
    """XOR two byte sequence."""
    return bytes(map(operator.xor, seq1, seq2))


def bits(num, width):
    """Convert number into a list of bits."""
    return [int(k) for k in f'{num:0{width}b}']

def get_prime_and_gen():
    ElGamalSystem = ElGamal.generate(512, get_random_bytes)
    return (int(ElGamalSystem.p), int(ElGamalSystem.g))


class PrimeGroup:
    """Cyclic abelian group of prime order 'prime'."""
    def __init__(self):
        self.prime, self.generator = get_prime_and_gen()
        self.prime_m1 = self.prime - 1
        self.prime_m2 = self.prime - 2
        

    def mul(self, num1, num2):
        "Multiply two elements." ""
        return (num1 * num2) % self.prime

    def pow(self, base, exponent):
        "Compute nth power of an element." ""
        return pow(base, exponent, self.prime)

    def gen_pow(self, exponent):  # generator exponentiation
        "Compute nth power of a generator." ""
        return pow(self.generator, exponent, self.prime)

    def inv(self, num):
        "Multiplicative inverse of an element." ""
        return pow(num, self.prime_m2, self.prime)

    def rand_int(self):  # random int in [1, prime-1]
        "Return an random int in [1, prime - 1]." ""
        return random.randint(1, self.prime_m1)