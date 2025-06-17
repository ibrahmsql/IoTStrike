/**
 * IoTStrike Hardware Security Framework
 * Performance Counter and Hardware Monitoring Assembly
 * 
 * @file performance_counters.s
 * @author ibrahimsql
 * @version 1.0.0
 * 
 * This file contains assembly routines for:
 * - Performance counter access
 * - Hardware event monitoring
 * - CPU feature detection
 * - Cache performance analysis
 * - Branch prediction monitoring
 */

#ifdef __x86_64__

.text
.global read_performance_counter
.global setup_performance_monitoring
.global read_cache_misses
.global read_branch_misses
.global read_instructions_retired
.global read_cycles_unhalted
.global enable_performance_counters
.global disable_performance_counters
.global read_msr
.global write_msr
.global cpuid_extended
.global measure_cache_latency
.global detect_cache_hierarchy

/**
 * Read performance counter
 * uint64_t read_performance_counter(uint32_t counter_id)
 */
read_performance_counter:
    movl %edi, %ecx        # Counter ID to ECX
    rdpmc                  # Read performance counter
    shlq $32, %rdx         # Shift high 32 bits
    orq %rdx, %rax         # Combine with low 32 bits
    ret

/**
 * Setup performance monitoring
 * void setup_performance_monitoring(void)
 */
setup_performance_monitoring:
    # Enable performance counters in CR4
    movq %cr4, %rax
    orq $0x100, %rax       # Set PCE bit (bit 8)
    movq %rax, %cr4
    
    # Setup IA32_PERFEVTSEL0 for cache misses
    movl $0x186, %ecx      # IA32_PERFEVTSEL0
    movl $0x41412E, %eax   # Event 0x2E (LLC misses), UMASK 0x41, USR+OS+EN
    xorl %edx, %edx
    wrmsr
    
    # Setup IA32_PERFEVTSEL1 for branch mispredictions
    movl $0x187, %ecx      # IA32_PERFEVTSEL1
    movl $0x4100C5, %eax   # Event 0xC5 (branch mispredictions), USR+OS+EN
    xorl %edx, %edx
    wrmsr
    
    # Setup IA32_PERFEVTSEL2 for instructions retired
    movl $0x188, %ecx      # IA32_PERFEVTSEL2
    movl $0x4100C0, %eax   # Event 0xC0 (instructions retired), USR+OS+EN
    xorl %edx, %edx
    wrmsr
    
    # Setup IA32_PERFEVTSEL3 for unhalted cycles
    movl $0x189, %ecx      # IA32_PERFEVTSEL3
    movl $0x41003C, %eax   # Event 0x3C (unhalted cycles), USR+OS+EN
    xorl %edx, %edx
    wrmsr
    
    ret

/**
 * Read cache misses counter
 * uint64_t read_cache_misses(void)
 */
read_cache_misses:
    xorl %ecx, %ecx        # Counter 0
    rdpmc
    shlq $32, %rdx
    orq %rdx, %rax
    ret

/**
 * Read branch misses counter
 * uint64_t read_branch_misses(void)
 */
read_branch_misses:
    movl $1, %ecx          # Counter 1
    rdpmc
    shlq $32, %rdx
    orq %rdx, %rax
    ret

/**
 * Read instructions retired counter
 * uint64_t read_instructions_retired(void)
 */
read_instructions_retired:
    movl $2, %ecx          # Counter 2
    rdpmc
    shlq $32, %rdx
    orq %rdx, %rax
    ret

/**
 * Read unhalted cycles counter
 * uint64_t read_cycles_unhalted(void)
 */
read_cycles_unhalted:
    movl $3, %ecx          # Counter 3
    rdpmc
    shlq $32, %rdx
    orq %rdx, %rax
    ret

/**
 * Enable performance counters
 * void enable_performance_counters(void)
 */
enable_performance_counters:
    # Reset all counters
    movl $0xC1, %ecx       # IA32_PMC0
    xorl %eax, %eax
    xorl %edx, %edx
    wrmsr
    
    movl $0xC2, %ecx       # IA32_PMC1
    wrmsr
    
    movl $0xC3, %ecx       # IA32_PMC2
    wrmsr
    
    movl $0xC4, %ecx       # IA32_PMC3
    wrmsr
    
    # Enable global performance monitoring
    movl $0x38F, %ecx      # IA32_PERF_GLOBAL_CTRL
    movl $0xF, %eax        # Enable counters 0-3
    xorl %edx, %edx
    wrmsr
    
    ret

/**
 * Disable performance counters
 * void disable_performance_counters(void)
 */
disable_performance_counters:
    movl $0x38F, %ecx      # IA32_PERF_GLOBAL_CTRL
    xorl %eax, %eax        # Disable all counters
    xorl %edx, %edx
    wrmsr
    ret

/**
 * Read MSR (Model Specific Register)
 * uint64_t read_msr(uint32_t msr_id)
 */
read_msr:
    movl %edi, %ecx        # MSR ID to ECX
    rdmsr                  # Read MSR
    shlq $32, %rdx         # Shift high 32 bits
    orq %rdx, %rax         # Combine with low 32 bits
    ret

/**
 * Write MSR (Model Specific Register)
 * void write_msr(uint32_t msr_id, uint64_t value)
 */
write_msr:
    movl %edi, %ecx        # MSR ID to ECX
    movq %rsi, %rax        # Value low 32 bits
    movq %rsi, %rdx
    shrq $32, %rdx         # Value high 32 bits
    wrmsr                  # Write MSR
    ret

/**
 * Extended CPUID with sub-leaf support
 * void cpuid_extended(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
 */
cpuid_extended:
    pushq %rbx             # Save rbx
    pushq %r10             # Save r10
    pushq %r11             # Save r11
    
    movl %edi, %eax        # Leaf
    movl %esi, %ecx        # Sub-leaf
    movq %rdx, %r10        # Save eax pointer
    movq %rcx, %r11        # Save ebx pointer
    
    cpuid                  # Execute CPUID
    
    movl %eax, (%r10)      # Store eax
    movl %ebx, (%r11)      # Store ebx
    movl %ecx, (%r8)       # Store ecx
    movl %edx, (%r9)       # Store edx
    
    popq %r11              # Restore r11
    popq %r10              # Restore r10
    popq %rbx              # Restore rbx
    ret

/**
 * Measure cache latency for different levels
 * uint64_t measure_cache_latency(void *addr, uint32_t iterations)
 */
measure_cache_latency:
    pushq %rbx
    pushq %rcx
    
    movq %rdi, %rbx        # Address
    movl %esi, %ecx        # Iterations
    xorq %rax, %rax        # Total cycles
    
.cache_latency_loop:
    mfence                 # Memory barrier
    rdtsc                  # Start timing
    movq %rax, %r8         # Save start (low)
    movq %rdx, %r9         # Save start (high)
    
    movq (%rbx), %r10      # Access memory
    
    rdtsc                  # End timing
    shlq $32, %rdx         # Combine end time
    orq %rdx, %rax
    
    shlq $32, %r9          # Combine start time
    orq %r9, %r8
    
    subq %r8, %rax         # Calculate difference
    addq %rax, %r11        # Accumulate total
    
    decl %ecx
    jnz .cache_latency_loop
    
    movq %r11, %rax        # Return total cycles
    
    popq %rcx
    popq %rbx
    ret

/**
 * Detect cache hierarchy information
 * void detect_cache_hierarchy(cache_info_t *info)
 */
detect_cache_hierarchy:
    pushq %rbx
    pushq %r12
    pushq %r13
    
    movq %rdi, %r12        # Save info pointer
    
    # Get cache information using CPUID leaf 4
    xorl %r13d, %r13d      # Cache level counter
    
.cache_detect_loop:
    movl $4, %eax          # CPUID leaf 4
    movl %r13d, %ecx       # Cache level
    cpuid
    
    # Check if cache level exists
    andl $0x1F, %eax       # Extract cache type
    testl %eax, %eax
    jz .cache_detect_done
    
    # Extract cache information
    movl %eax, %r8d        # Cache type and level
    movl %ebx, %r9d        # Cache size info
    movl %ecx, %r10d       # Cache sets
    movl %edx, %r11d       # Cache features
    
    # Store cache information (simplified)
    movq %r12, %rdi
    addq %r13, %rdi
    shlq $4, %rdi          # Each entry is 16 bytes
    
    movl %r8d, (%rdi)      # Store cache type
    movl %r9d, 4(%rdi)     # Store size info
    movl %r10d, 8(%rdi)    # Store sets
    movl %r11d, 12(%rdi)   # Store features
    
    incl %r13d
    cmpl $8, %r13d         # Max 8 cache levels
    jl .cache_detect_loop
    
.cache_detect_done:
    popq %r13
    popq %r12
    popq %rbx
    ret

#elif defined(__aarch64__)

.text
.global read_performance_counter_arm64
.global setup_performance_monitoring_arm64
.global read_cycle_counter_arm64
.global read_instruction_counter_arm64
.global enable_user_access_arm64
.global read_cache_events_arm64

/**
 * Read performance counter (ARM64)
 * uint64_t read_performance_counter_arm64(uint32_t counter_id)
 */
read_performance_counter_arm64:
    cmp w0, #0
    b.eq .read_pmc0
    cmp w0, #1
    b.eq .read_pmc1
    cmp w0, #2
    b.eq .read_pmc2
    cmp w0, #3
    b.eq .read_pmc3
    mov x0, #0
    ret

.read_pmc0:
    mrs x0, pmevcntr0_el0
    ret

.read_pmc1:
    mrs x0, pmevcntr1_el0
    ret

.read_pmc2:
    mrs x0, pmevcntr2_el0
    ret

.read_pmc3:
    mrs x0, pmevcntr3_el0
    ret

/**
 * Setup performance monitoring (ARM64)
 * void setup_performance_monitoring_arm64(void)
 */
setup_performance_monitoring_arm64:
    // Enable performance monitoring
    mrs x0, pmcr_el0
    orr x0, x0, #1         // Enable bit
    orr x0, x0, #2         // Reset cycle counter
    orr x0, x0, #4         // Reset event counters
    msr pmcr_el0, x0
    
    // Enable counters
    mov x0, #0xF           // Enable counters 0-3
    msr pmcntenset_el0, x0
    
    // Setup event types
    mov x0, #0x11          // L1D cache miss
    msr pmevtyper0_el0, x0
    
    mov x0, #0x10          // L1I cache miss
    msr pmevtyper1_el0, x0
    
    mov x0, #0x08          // Instruction retired
    msr pmevtyper2_el0, x0
    
    mov x0, #0x1B          // L2D cache miss
    msr pmevtyper3_el0, x0
    
    ret

/**
 * Read cycle counter (ARM64)
 * uint64_t read_cycle_counter_arm64(void)
 */
read_cycle_counter_arm64:
    mrs x0, pmccntr_el0
    ret

/**
 * Read instruction counter (ARM64)
 * uint64_t read_instruction_counter_arm64(void)
 */
read_instruction_counter_arm64:
    mrs x0, pmevcntr2_el0
    ret

/**
 * Enable user access to performance counters (ARM64)
 * void enable_user_access_arm64(void)
 */
enable_user_access_arm64:
    mrs x0, pmuserenr_el0
    orr x0, x0, #1         // Enable user access
    msr pmuserenr_el0, x0
    ret

/**
 * Read cache events (ARM64)
 * void read_cache_events_arm64(uint64_t *l1d_miss, uint64_t *l1i_miss, uint64_t *l2d_miss)
 */
read_cache_events_arm64:
    mrs x3, pmevcntr0_el0  // L1D cache miss
    str x3, [x0]
    
    mrs x3, pmevcntr1_el0  // L1I cache miss
    str x3, [x1]
    
    mrs x3, pmevcntr3_el0  // L2D cache miss
    str x3, [x2]
    
    ret

#endif

.const
.global performance_counter_names
performance_counter_names:
    .ascii "Cache Misses\0"
    .ascii "Branch Mispredictions\0"
    .ascii "Instructions Retired\0"
    .ascii "Cycles Unhalted\0"
    .ascii "L1D Cache Misses\0"
    .ascii "L1I Cache Misses\0"
    .ascii "L2 Cache Misses\0"
    .ascii "TLB Misses\0"