# Bakery Simulation

Discrete-event simulation of a bakery service system with constrained resources.

## Model

- 25-person maximum capacity
- 4-seat sofa (waiting area)
- 4 ovens and 4 chefs
- Single cash register
- FIFO scheduling with priority: payment acceptance takes precedence over starting new bakes

## Files

- `main.c` -- entire simulation (event loop with 1-second time steps, resource management, customer lifecycle)

## Build and Run

```
make
./bakery < input.txt
```

Input format: one customer arrival time per line.