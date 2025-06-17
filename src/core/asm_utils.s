/**
 * IoTStrike Hardware Security Framework
 * Assembly Utilities for Low-Level Hardware Manipulation
 * 
 * @file asm_utils.s
 * @author ibrahimsql
 * @version 1.0.0
 * 
 * This file contains architecture-specific assembly routines for:
 * - Cache manipulation
 * - Memory barriers
 * - Atomic operations
 * - CPU feature detection
 * - Performance counters
 * - Side-channel attack primitives
 */

#ifdef __x86_64__

.text
.global flush_cache_line
.global memory_barrier
.global atomic_increment
.global get_cpu_cycles
.global get_cpu_features
.global timing_attack_primitive
.global cache_timing_attack
.global speculative_execution_barrier

/**
 * Flush a cache line containing the specified address
 * void flush_cache_line(void *addr)
 */
flush_cache_line:
    clflush (%rdi)          # Flush cache line containing address in rdi
    ret

/**
 * Full memory barrier
 * void memory_barrier(void)
 */
memory_barrier:
    mfence                  # Memory fence - serialize all memory operations
    ret

/**
 * Atomic increment of a 32-bit value
 * int atomic_increment(int *value)
 */
atomic_increment:
    movl $1, %eax          # Load 1 into eax
    lock xaddl %eax, (%rdi) # Atomic exchange and add
    incl %eax              # Return value + 1
    ret

/**
 * Get CPU cycle counter (RDTSC)
 * uint64_t get_cpu_cycles(void)
 */
get_cpu_cycles:
    rdtsc                   # Read time-stamp counter
    shlq $32, %rdx         # Shift high 32 bits
    orq %rdx, %rax         # Combine with low 32 bits
    ret

/**
 * Get CPU features using CPUID
 * void get_cpu_features(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
 */
get_cpu_features:
    pushq %rbx             # Save rbx (callee-saved)
    movl $1, %eax          # CPUID function 1 (processor info)
    cpuid                  # Execute CPUID
    
    movl %eax, (%rdi)      # Store eax
    movl %ebx, (%rsi)      # Store ebx
    movl %ecx, (%rdx)      # Store ecx
    movl %edx, (%rcx)      # Store edx
    
    popq %rbx              # Restore rbx
    ret

/**
 * Timing attack primitive - measure memory access time
 * uint64_t timing_attack_primitive(void *addr)
 */
timing_attack_primitive:
    mfence                 # Serialize before measurement
    rdtsc                  # Get start time
    movq %rax, %r8         # Save start time (low)
    movq %rdx, %r9         # Save start time (high)
    
    movq (%rdi), %r10      # Access memory location
    
    rdtsc                  # Get end time
    shlq $32, %rdx         # Shift high bits
    orq %rdx, %rax         # Combine end time
    
    shlq $32, %r9          # Shift start high bits
    orq %r9, %r8           # Combine start time
    
    subq %r8, %rax         # Calculate difference
    ret

/**
 * Cache timing attack - probe cache line
 * uint64_t cache_timing_attack(void *addr)
 */
cache_timing_attack:
    mfence                 # Memory barrier
    lfence                 # Load fence
    rdtsc                  # Start timing
    movq %rax, %r8         # Save start (low)
    movq %rdx, %r9         # Save start (high)
    
    movb (%rdi), %al       # Load byte from address
    
    lfence                 # Load fence
    rdtsc                  # End timing
    shlq $32, %rdx         # Combine end time
    orq %rdx, %rax
    
    shlq $32, %r9          # Combine start time
    orq %r9, %r8
    
    subq %r8, %rax         # Calculate timing difference
    ret

/**
 * Speculative execution barrier
 * void speculative_execution_barrier(void)
 */
speculative_execution_barrier:
    lfence                 # Load fence to prevent speculation
    ret

#elif defined(__aarch64__)

.text
.global flush_cache_line_arm64
.global memory_barrier_arm64
.global atomic_increment_arm64
.global get_cpu_cycles_arm64
.global timing_attack_primitive_arm64
.global cache_timing_attack_arm64

/**
 * Flush cache line (ARM64)
 * void flush_cache_line_arm64(void *addr)
 */
flush_cache_line_arm64:
    dc civac, x0           // Clean and invalidate cache line
    dsb sy                 // Data synchronization barrier
    ret

/**
 * Memory barrier (ARM64)
 * void memory_barrier_arm64(void)
 */
memory_barrier_arm64:
    dsb sy                 // Data synchronization barrier (system)
    isb                    // Instruction synchronization barrier
    ret

/**
 * Atomic increment (ARM64)
 * int atomic_increment_arm64(int *value)
 */
atomic_increment_arm64:
1:  ldxr w1, [x0]         // Load exclusive
    add w1, w1, #1         // Increment
    stxr w2, w1, [x0]      // Store exclusive
    cbnz w2, 1b            // Retry if store failed
    mov w0, w1             // Return new value
    ret

/**
 * Get CPU cycles (ARM64 - using virtual counter)
 * uint64_t get_cpu_cycles_arm64(void)
 */
get_cpu_cycles_arm64:
    mrs x0, cntvct_el0     // Read virtual counter
    ret

/**
 * Timing attack primitive (ARM64)
 * uint64_t timing_attack_primitive_arm64(void *addr)
 */
timing_attack_primitive_arm64:
    dsb sy                 // Data synchronization barrier
    isb                    // Instruction synchronization barrier
    mrs x1, cntvct_el0     // Get start time
    
    ldr x2, [x0]           // Access memory
    
    mrs x0, cntvct_el0     // Get end time
    sub x0, x0, x1         // Calculate difference
    ret

/**
 * Cache timing attack (ARM64)
 * uint64_t cache_timing_attack_arm64(void *addr)
 */
cache_timing_attack_arm64:
    dsb sy                 // Data synchronization barrier
    isb                    // Instruction synchronization barrier
    mrs x1, cntvct_el0     // Start timing
    
    ldrb w2, [x0]          // Load byte
    
    dsb sy                 // Data synchronization barrier
    mrs x0, cntvct_el0     // End timing
    sub x0, x0, x1         // Calculate difference
    ret

/**
 * Functions called by Zig timing analysis code (ARM64)
 */
.global _readTSC
.global _readCacheMisses
.global _readBranchMisses
.global _flushCacheLine

/**
 * Read Time Stamp Counter (ARM64)
 * uint64_t readTSC(void)
 */
_readTSC:
    mrs x0, cntvct_el0     // Read virtual counter
    ret

/**
 * Read cache misses (simplified implementation)
 * uint32_t readCacheMisses(void)
 */
_readCacheMisses:
    mov w0, #0             // Return 0 for now
    ret

/**
 * Read branch misses (simplified implementation)
 * uint32_t readBranchMisses(void)
 */
_readBranchMisses:
    mov w0, #0             // Return 0 for now
    ret

/**
 * Flush cache line (ARM64)
 * void flushCacheLine(void *addr)
 */
_flushCacheLine:
    dc civac, x0           // Clean and invalidate cache line
    dsb sy                 // Data synchronization barrier
    ret

#elif defined(__arm__)

.text
.global flush_cache_line_arm
.global memory_barrier_arm
.global atomic_increment_arm
.global get_cpu_cycles_arm
.global timing_attack_primitive_arm

/**
 * Flush cache line (ARM32)
 * void flush_cache_line_arm(void *addr)
 */
flush_cache_line_arm:
    mcr p15, 0, r0, c7, c14, 1  @ Clean and invalidate cache line
    dsb                         @ Data synchronization barrier
    bx lr

/**
 * Memory barrier (ARM32)
 * void memory_barrier_arm(void)
 */
memory_barrier_arm:
    dsb                    @ Data synchronization barrier
    isb                    @ Instruction synchronization barrier
    bx lr

/**
 * Atomic increment (ARM32)
 * int atomic_increment_arm(int *value)
 */
atomic_increment_arm:
1:  ldrex r1, [r0]        @ Load exclusive
    add r1, r1, #1         @ Increment
    strex r2, r1, [r0]     @ Store exclusive
    cmp r2, #0             @ Check if store succeeded
    bne 1b                 @ Retry if failed
    mov r0, r1             @ Return new value
    bx lr

/**
 * Get CPU cycles (ARM32 - using cycle counter if available)
 * uint64_t get_cpu_cycles_arm(void)
 */
get_cpu_cycles_arm:
    mrc p15, 0, r0, c9, c13, 0  @ Read cycle counter (if available)
    mov r1, #0                  @ High 32 bits (not available on ARM32)
    bx lr

/**
 * Timing attack primitive (ARM32)
 * uint32_t timing_attack_primitive_arm(void *addr)
 */
timing_attack_primitive_arm:
    dsb                         @ Data synchronization barrier
    mrc p15, 0, r1, c9, c13, 0  @ Get start time
    
    ldr r2, [r0]               @ Access memory
    
    mrc p15, 0, r0, c9, c13, 0  @ Get end time
    sub r0, r0, r1             @ Calculate difference
    bx lr

#endif

/**
 * Common macros and constants
 */

#ifdef __x86_64__

.const
.global cache_line_size
.global page_size

cache_line_size:
    .quad 64               /* Typical x86_64 cache line size */

page_size:
    .quad 4096             /* Typical x86_64 page size */

#elif defined(__aarch64__)

.const
.global cache_line_size_arm64
.global page_size_arm64

cache_line_size_arm64:
    .quad 64               /* Typical ARM64 cache line size */

page_size_arm64:
    .quad 4096             /* Typical ARM64 page size */

#elif defined(__arm__)

.const
.global cache_line_size_arm
.global page_size_arm

cache_line_size_arm:
    .word 32               /* Typical ARM32 cache line size */

page_size_arm:
    .word 4096             /* Typical ARM32 page size */

#endif

/**
 * Side-channel attack primitives
 */

#ifdef __x86_64__

.text
.global prime_cache
.global probe_cache
.global flush_reload_attack

/**
 * Prime cache with specific pattern
 * void prime_cache(void *start_addr, size_t size)
 */
prime_cache:
    movq %rdi, %rax        # Start address
    addq %rsi, %rdi        # End address
    
1:  movq (%rax), %rdx    # Load from cache line
    addq $64, %rax         # Next cache line
    cmpq %rdi, %rax        # Check if done
    jl 1b                  # Continue if not done
    
    ret

/**
 * Probe cache and measure timing
 * uint64_t probe_cache(void *start_addr, size_t size)
 */
probe_cache:
    movq %rdi, %r8         # Start address
    addq %rsi, %rdi        # End address
    xorq %rax, %rax        # Clear result
    
1:  mfence                # Memory barrier
    rdtsc                  # Start timing
    movq %rax, %r9         # Save start time
    
    movq (%r8), %rdx       # Access memory
    
    rdtsc                  # End timing
    subq %r9, %rax         # Calculate difference
    
    addq $64, %r8          # Next cache line
    cmpq %rdi, %r8         # Check if done
    jl 1b                  # Continue if not done
    
    ret

/**
 * Flush+Reload attack primitive
 * uint64_t flush_reload_attack(void *addr)
 */
flush_reload_attack:
    clflush (%rdi)         # Flush target address
    mfence                 # Memory barrier
    
    # Wait for victim to potentially access
    movq $1000, %rcx       # Wait counter
2:  pause                  # Pause instruction
    loop 2b                # Decrement and loop
    
    # Measure reload time
    mfence                 # Memory barrier
    rdtsc                  # Start timing
    movq %rax, %r8         # Save start time
    
    movq (%rdi), %rdx      # Reload data
    
    rdtsc                  # End timing
    subq %r8, %rax         # Calculate difference
    
    ret

#endif

/**
 * Performance monitoring primitives
 */

#ifdef __x86_64__

.text
.global read_pmc
.global enable_pmc

/**
 * Read performance monitoring counter
 * uint64_t read_pmc(uint32_t counter)
 */
read_pmc:
    movl %edi, %ecx        # Counter number
    rdpmc                  # Read performance counter
    shlq $32, %rdx         # Shift high bits
    orq %rdx, %rax         # Combine result
    ret

/**
 * Enable performance monitoring (requires privileges)
 * void enable_pmc(void)
 */
enable_pmc:
    # This would require kernel-level access
    # Placeholder for demonstration
    ret

#endif

/**
 * Fault injection primitives
 */

#ifdef __x86_64__

.text
.global voltage_glitch_trigger
.global clock_glitch_trigger

/**
 * Trigger point for voltage glitch injection
 * void voltage_glitch_trigger(void)
 */
voltage_glitch_trigger:
    # Specific instruction sequence that can be targeted
    nop                    # Target instruction 1
    nop                    # Target instruction 2
    nop                    # Target instruction 3
    nop                    # Target instruction 4
    ret

/**
 * Trigger point for clock glitch injection
 * void clock_glitch_trigger(void)
 */
clock_glitch_trigger:
    # Critical timing-sensitive operation
    rdtsc                  # Read timestamp
    movq %rax, %rdx        # Move to register
    rdtsc                  # Read again
    subq %rdx, %rax        # Calculate difference
    ret



#endif

/**
 * Memory protection bypass primitives
 */

#ifdef __x86_64__

.text
.global smep_bypass_gadget
.global smap_bypass_gadget

/**
 * SMEP bypass gadget (Supervisor Mode Execution Prevention)
 * void smep_bypass_gadget(void)
 */
smep_bypass_gadget:
    # This would be used in kernel exploits
    # Placeholder for demonstration
    popq %rax              # Pop return address
    ret                    # Return

/**
 * SMAP bypass gadget (Supervisor Mode Access Prevention)
 * void smap_bypass_gadget(void)
 */
smap_bypass_gadget:
    # This would be used in kernel exploits
    # Placeholder for demonstration
    clac                   # Clear AC flag
    ret                    # Return

#endif