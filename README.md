# xv6 Sniffer and Paging

Systems programming project with three components built in C, covering OS internals, network packet analysis, and concurrency simulation.

## Part A — Demand Paging in xv6 (RISC-V)

Modified the xv6 operating system kernel to implement **demand paging** — pages are allocated lazily on first access rather than eagerly at process creation. Key changes span the kernel's virtual memory subsystem (`vm.c`), trap handler (`trap.c`), process management (`proc.c`), and memory allocator (`kalloc.c`).

- Lazy page allocation with page fault handling
- Memory statistics tracking via custom `memstat` syscall
- Fork-aware page table management
- Test programs: `demandtest.c`, `forkpagetest.c`, `dirtytest.c`

**Built on:** MIT's xv6-riscv teaching OS

## Part B — C-Shark: Terminal Packet Sniffer

A command-line network packet sniffer written in C. Parses and inspects raw packet captures (pcap format) with modular architecture.

- Packet parsing and protocol inspection
- PCAP file handling
- Modular source structure (`packet_parser`, `pcap_handler`, `inspector`, `packet_storage`)

## Part C — Bakery Simulation

A discrete-event simulation of a bakery service system, modeling customer flow with constrained resources (4 ovens, 4 chefs, 4-seat sofa, 25-person capacity). Implements FIFO scheduling with priority-based task assignment.

- Event-driven simulation loop (1-second time steps)
- Resource contention: ovens, chefs, cash register, seating
- Priority scheduling: payment acceptance takes precedence over baking

## Build

**Part A (xv6):**
```bash
cd A
make qemu
```
Requires RISC-V toolchain and QEMU for riscv64.

**Part B (C-Shark):**
```bash
cd B
make
./bin/cshark
```

**Part C (Bakery):**
```bash
cd C
make
./bakery < input.txt
```
