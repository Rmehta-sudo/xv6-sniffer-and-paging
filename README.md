# xv6 Modifications, Packet Sniffer, and Bakery Simulation

Three systems programming assignments in C covering OS kernel modifications, network packet analysis, and concurrency simulation.

## Part A -- Demand Paging in xv6 (RISC-V)

Modified the xv6 kernel to implement demand paging -- pages are allocated lazily on first access instead of eagerly at process creation. Key changes in `vm.c` (page fault handler), `trap.c`, `proc.c`, and `kalloc.c`.

- Lazy page allocation with page fault handling
- Memory stats tracking via custom `memstat` syscall
- Fork-aware page table management
- Test programs: `demandtest.c`, `forkpagetest.c`, `dirtytest.c`

```
cd A
make qemu
```
Requires RISC-V toolchain and QEMU.

## Part B -- C-Shark: Terminal Packet Sniffer

Command-line packet sniffer that parses raw pcap captures. Modular architecture with separate modules for packet parsing, pcap file handling, protocol inspection, and storage.

```
cd B
make
./bin/cshark
```

## Part C -- Bakery Simulation

Discrete-event simulation of a bakery with constrained resources (4 ovens, 4 chefs, 4-seat sofa, 25-person capacity). Implements FIFO scheduling with priority-based task assignment (payment over baking).

```
cd C
make
./bakery < input.txt
```

## Structure

```
A/               -- xv6 kernel source (demand paging modifications)
B/               -- packet sniffer (src/ for parser, inspector, pcap handler)
C/               -- bakery simulation (single-file main.c)
```
