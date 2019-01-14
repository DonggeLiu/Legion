import claripy
import pdb

solver = claripy.Solver(backend=claripy.backend_manager.backends._all_backends[2])

x = claripy.BVS("x", 8)
y = claripy.BVV(100, 8)

solver.add(x < y)

values = []
while True:
    value = solver.eval(x, 10)
    print("new value group:", value)
    values.append(sorted(value))
    if len(value) < 10:
        break

print(len(values), sorted(values))
