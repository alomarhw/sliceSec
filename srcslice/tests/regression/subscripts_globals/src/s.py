from qiskit import QuantumCircuit, QuantumRegister

q = QuantumRegister(4)
qc = QuantumCircuit(q)
a = 1
qc.h(q[a])
theta = [0.1, 0.2]
k = 0
x = theta[k]
EDGES = [(0, 1), (1, 2)]


def layer(circ):
    for u, v in EDGES:
        circ.cx(q[u], q[v])
    local = EDGES
    EDGES2 = 3
