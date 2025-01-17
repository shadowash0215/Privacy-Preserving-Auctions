from os import urandom
from pickle import dumps
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

def getrandbits(nbits):
    return bytes_to_long(urandom((nbits + 7) >> 3)) >> (7 - ((nbits - 1) & 7))  

class fixed_key:

    def __init__(self):
        self.key = urandom(16)
    
    def encrypt(self, input):
        aes = AES.new(self.key, AES.MODE_ECB)
        return bytes_to_long(aes.encrypt(long_to_bytes(input).zfill(16)))

class wire:

    def __init__(self):
        global wires
        self.index = len(wires)
        wires.append(self)
        self.bit_table = getrandbits(1)
        self.value_table = { 0: getrandbits(127) * 2 + self.bit_table, 1: getrandbits(127) * 2 + ~self.bit_table }

    def _get_garbled(self, bit):
        return self.value_table[bit]
    
    def _de_garbled(self, value):
        if self.value_table[0] == value: return 0
        if self.value_table[1] == value: return 1
        raise ValueError("Invalid garbled value")
    
    def get_index(self):
        return self.index

class module:

    global gates, wires, memory

    wires = []
    gates = {}
    memory = {}

    def get_outputs(self) -> list:
        return self.outputs
    
    def evaluate(self, input: dict) -> dict:
        result = {}
        for out in self.outputs:
            result[out] = gates[out].recursive_evaluate(input)
        return result

class gate(module):

    def __init__(self, index1: int, index2: int, func):
        global wires, gates
        input1 = wires[index1]
        input2 = wires[index2]
        self.garbled_table = {}
        output = wire()
        self.index = output.index
        self.i1 = index1
        self.i2 = index2
        self.prng = fixed_key()
        for i in range(2):
            for j in range(2):
                X_a = input1.value_table[i]
                X_b = input2.value_table[j]
                X_c = output._get_garbled(func(i, j))
                K = (X_a * 2 ^ X_b * 4 ^ self.index) & (2 ** 128 - 1)
                # print(f"K = {K}")
                self.garbled_table[(X_a & 1, X_b & 1)] = self.prng.encrypt(K) ^ K ^ X_c
                # print(f"{(X_a, X_b)}: {self.prng.encrypt(K) ^ K ^ X_c}")
        gates[self.index] = self

    def recursive_evaluate(self, inputs:dict):
        global memory
        if self.get_index() in memory:
            return memory[self.get_index()]
        input1 = None
        input2 = None
        if self.i1 not in inputs:
            input1 = gates[self.i1].recursive_evaluate(inputs)
        else:
            input1 = inputs[self.i1]
        if self.i2 not in inputs:
            input2 = gates[self.i2].recursive_evaluate(inputs)
        else:
            input2 = inputs[self.i2]
        result = self.evaluate(input1, input2)
        memory[self.get_index()] = result
        return result

    def get_entry(self, i, j):            
        return self.garbled_table[(i, j)]
    
    def get_index(self):
        return self.index

    def evaluate(self, input1, input2):
        enc = self.get_entry(input1 & 1, input2 & 1)
        K = (input1 * 2 ^ input2 * 4 ^ self.index) & (2 ** 128 - 1)
        result = enc ^ K ^ self.prng.encrypt(K)
        return result
    
class sne_nbit(module):
    def __init__(self, nbits:int, input1: list, input2: list):
        assert len(input1) == nbits, "length error!"
        assert len(input2) == nbits, "length error!"
        self.outputs = []
        temp_gates = []
        temp_gates.append(gate(input1[0], input2[0], lambda a, b: a ^ b))
        for i in range(1, nbits):
            g1 = gate(input1[i], input2[i], lambda a, b: a ^ b)
            g2 = gate(g1.get_index(), temp_gates[-1].get_index(), lambda a, b: a or b)
            temp_gates.append(g1)
            temp_gates.append(g2)
        self.outputs.append(temp_gates[-1].get_index())

class slt_nbit(module):

    def __init__(self, nbits:int, input1: list, input2: list):
        assert len(input1) == nbits, "length error!"
        assert len(input2) == nbits, "length error!"
        self.outputs = []
        temp_gates = []
        temp_gates.append(gate(input1[0], input2[0], lambda a, b: not a and b))
        for i in range(1, nbits):
            g1 = gate(input1[i], input2[i], lambda a, b: not a and b)
            g2 = gate(input1[i], input2[i], lambda a, b: not (a ^ b))
            g3 = gate(g2.get_index(), temp_gates[-1].get_index(), lambda a, b: a and b)
            g4 = gate(g1.get_index(), g3.get_index(), lambda a, b: a or b)
            temp_gates.append(g1)
            temp_gates.append(g2)
            temp_gates.append(g3)
            temp_gates.append(g4)
        self.outputs.append(temp_gates[-1].get_index())

class and_nbit(module):

    def __init__(self, nbits:int, input1: list, input2: list):
        assert len(input1) == nbits, "length error!"
        assert len(input2) == nbits, "length error!"
        self.outputs = []
        temp_gates = []
        for i in range(nbits):
            g1 = gate(input1[i], input2[i], lambda a, b: a and b)
            temp_gates.append(g1)
            self.outputs.append(temp_gates[-1].get_index())

class mux2_nbit(module):

    def __init__(self, nbits:int, input1: list, input2: list, sel):
        assert len(input1) == nbits, "length error!"
        assert len(input2) == nbits, "length error!"
        self.outputs = []
        temp_gates = []
        for i in range(nbits):
            g1 = gate(input1[i], sel, lambda a, b: a and not b)
            g2 = gate(input2[i], sel, lambda a, b: a and b)
            g3 = gate(g1.get_index(), g2.get_index(), lambda a, b: a or b)
            temp_gates.append(g1)
            temp_gates.append(g2)
            temp_gates.append(g3)
            self.outputs.append(g3.get_index())

class max_nbit(module):

    def __init__(self, nbits: int, input1: list, input2: list):
        assert len(input1) == nbits, "length error!"
        assert len(input2) == nbits, "length error!"
        self.outputs = []
        temp_modules = []
        temp_modules.append(slt_nbit(nbits, input1, input2))
        sel = temp_modules[-1].get_outputs()[0]
        temp_modules.append(mux2_nbit(nbits, input1, input2, sel))
        self.outputs = temp_modules[-1].get_outputs()[::]

class maxm_nbit(module):

    def __init__(self, nbits: int, inputs: list):
        m = len(inputs)
        assert len(inputs[0]) == nbits, "length error!"
        self.outputs = []
        temp_modules = []
        premax = inputs[0]
        for i in range(1, m):
            assert len(inputs[i]) == nbits, "length error!"
            temp_modules.append(max_nbit(nbits, premax, inputs[i]))
            premax = temp_modules[-1].get_outputs()[::]
        self.outputs = premax[::]

class max2ndm_nbit(module):

    def __init__(self, nbits: int, inputs: list):
        self.outputs = []
        temp_modules = []
        temp_modules.append(maxm_nbit(nbits, inputs))
        maxm = temp_modules[-1].get_outputs()[::]
        inputs2nd = []
        for input in inputs:
            temp_modules.append(sne_nbit(nbits, maxm, input))
            notmax = temp_modules[-1].get_outputs()[0]
            self.outputs.append(notmax)
            temp_modules.append(and_nbit(nbits, input, [notmax] * nbits))
            inputs2nd.append(temp_modules[-1].get_outputs()[::])
        temp_modules.append(maxm_nbit(nbits, inputs2nd))
        self.outputs += temp_modules[-1].get_outputs()[::]

def testcase():
    mbidder = 8
    nbits = 8
    bids = [
        [0, 1, 1, 0, 0, 1, 0, 0],   # 0b00100110 = 38
        [1, 1, 1, 0, 1, 0, 1, 0],   # 0b01010111 = 87
        [0, 0, 1, 0, 1, 1, 1, 0],   # 0b01110100 = 116
        [1, 0, 0, 1, 1, 1, 0, 0],   # 0b00111001 = 57
        [1, 1, 0, 0, 0, 0, 1, 0],   # 0b01000011 = 67
        [0, 1, 1, 1, 1, 0, 1, 1],   # 0b11011110 = 222
        [1, 0, 0, 0, 0, 1, 1, 0],   # 0b01100001 = 97
        [0, 1, 1, 1, 1, 0, 0, 1],   # 0b10011110 = 158
    ]
    inputs = {}
    for i in range(mbidder):
        for j in range(nbits):
            w = wire()
            inputs[w.get_index()] = w._get_garbled(bids[i][j])
            bids[i][j] = w.get_index()
    circuit = max2ndm_nbit(nbits, bids)
    print(f"{len(wires)} wires and {len(gates)} gates generated.")
    answer = circuit.evaluate(inputs)
    print("Highest bidder:", end=" ")
    for i in range(mbidder):
        if wires[circuit.outputs[i]]._de_garbled(answer[circuit.outputs[i]]) == 0:
            print(f"Bidder {i}", end=" ")
    price = 0
    for i in range(nbits):
        price += wires[circuit.outputs[i+mbidder]]._de_garbled(answer[circuit.outputs[i+mbidder]]) << i
    print(f"\n2nd highest price: {price}")
    print(f"Object packed in {len(dumps([circuit, wires, gates]))} bytes")

if __name__ == "__main__":
    testcase()