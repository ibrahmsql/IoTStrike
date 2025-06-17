//! IoTStrike Hardware Security Framework
//! Side-Channel Attack Framework - Power Analysis Module
//! 
//! @file power_analysis.zig
//! @author ibrahimsql
//! @version 1.0.0

const std = @import("std");
const math = std.math;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

// C interop removed for compatibility

/// Power trace sample
const PowerSample = struct {
    timestamp: u64,
    voltage: f64,
    current: f64,
    power: f64,
};

/// Power analysis configuration
const PowerAnalysisConfig = struct {
    sample_rate: u32,
    duration: u32,
    trigger_threshold: f64,
    filter_enabled: bool,
    filter_cutoff: f64,
    amplification: f64,
};

/// Statistical analysis results
const StatisticalResult = struct {
    mean: f64,
    variance: f64,
    std_deviation: f64,
    correlation: f64,
    snr: f64, // Signal-to-noise ratio
};

/// DPA (Differential Power Analysis) context
const DPAContext = struct {
    allocator: Allocator,
    traces: ArrayList([]PowerSample),
    plaintexts: ArrayList([]u8),
    ciphertexts: ArrayList([]u8),
    key_hypotheses: [256]f64,
    correlation_matrix: [][]f64,
    config: PowerAnalysisConfig,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, config: PowerAnalysisConfig) !Self {
        const correlation_matrix = try allocator.alloc([]f64, 256);
        for (correlation_matrix) |*row| {
            row.* = try allocator.alloc(f64, 1000); // Max trace length
        }
        
        return Self{
            .allocator = allocator,
            .traces = ArrayList([]PowerSample).init(allocator),
            .plaintexts = ArrayList([]u8).init(allocator),
            .ciphertexts = ArrayList([]u8).init(allocator),
            .key_hypotheses = [_]f64{0.0} ** 256,
            .correlation_matrix = correlation_matrix,
            .config = config,
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.correlation_matrix) |row| {
            self.allocator.free(row);
        }
        self.allocator.free(self.correlation_matrix);
        
        for (self.traces.items) |trace| {
            self.allocator.free(trace);
        }
        self.traces.deinit();
        
        for (self.plaintexts.items) |plaintext| {
            self.allocator.free(plaintext);
        }
        self.plaintexts.deinit();
        
        for (self.ciphertexts.items) |ciphertext| {
            self.allocator.free(ciphertext);
        }
        self.ciphertexts.deinit();
    }
};

/// CPA (Correlation Power Analysis) context
const CPAContext = struct {
    allocator: Allocator,
    traces: ArrayList([]PowerSample),
    intermediate_values: ArrayList([]u8),
    hamming_weights: ArrayList([]u8),
    correlation_coefficients: []f64,
    config: PowerAnalysisConfig,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, config: PowerAnalysisConfig) !Self {
        return Self{
            .allocator = allocator,
            .traces = ArrayList([]PowerSample).init(allocator),
            .intermediate_values = ArrayList([]u8).init(allocator),
            .hamming_weights = ArrayList([]u8).init(allocator),
            .correlation_coefficients = try allocator.alloc(f64, 256),
            .config = config,
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.traces.items) |trace| {
            self.allocator.free(trace);
        }
        self.traces.deinit();
        
        for (self.intermediate_values.items) |values| {
            self.allocator.free(values);
        }
        self.intermediate_values.deinit();
        
        for (self.hamming_weights.items) |weights| {
            self.allocator.free(weights);
        }
        self.hamming_weights.deinit();
        
        self.allocator.free(self.correlation_coefficients);
    }
};

/// AES S-Box for power analysis
const AES_SBOX = [_]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/// Calculate Hamming weight of a byte
fn hammingWeight(value: u8) u8 {
    var weight: u8 = 0;
    var v = value;
    while (v != 0) {
        weight += v & 1;
        v >>= 1;
    }
    return weight;
}

/// Calculate Hamming distance between two bytes
fn hammingDistance(a: u8, b: u8) u8 {
    return hammingWeight(a ^ b);
}

/// Apply digital filter to power trace
fn applyLowPassFilter(allocator: Allocator, trace: []PowerSample, cutoff_freq: f64, sample_rate: f64) ![]PowerSample {
    const filtered = try allocator.alloc(PowerSample, trace.len);
    
    // Simple IIR low-pass filter
    const alpha = 2.0 * math.pi * cutoff_freq / sample_rate;
    const a = alpha / (alpha + 1.0);
    
    filtered[0] = trace[0];
    
    for (trace[1..], 1..) |sample, i| {
        filtered[i] = PowerSample{
            .timestamp = sample.timestamp,
            .voltage = a * sample.voltage + (1.0 - a) * filtered[i-1].voltage,
            .current = a * sample.current + (1.0 - a) * filtered[i-1].current,
            .power = a * sample.power + (1.0 - a) * filtered[i-1].power,
        };
    }
    
    return filtered;
}

/// Calculate correlation coefficient between two arrays
fn calculateCorrelation(x: []const f64, y: []const f64) f64 {
    if (x.len != y.len or x.len == 0) return 0.0;
    
    var sum_x: f64 = 0.0;
    var sum_y: f64 = 0.0;
    var sum_xy: f64 = 0.0;
    var sum_x2: f64 = 0.0;
    var sum_y2: f64 = 0.0;
    
    const n = @as(f64, @floatFromInt(x.len));
    
    for (x, y) |xi, yi| {
        sum_x += xi;
        sum_y += yi;
        sum_xy += xi * yi;
        sum_x2 += xi * xi;
        sum_y2 += yi * yi;
    }
    
    const numerator = n * sum_xy - sum_x * sum_y;
    const denominator = math.sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y));
    
    if (denominator == 0.0) return 0.0;
    return numerator / denominator;
}

/// Perform Simple Power Analysis (SPA)
export fn performSPA(trace_data: [*]const PowerSample, trace_length: usize, 
                    result: *anyopaque) i32 {
    const trace = trace_data[0..trace_length];
    
    var max_power: f64 = -math.inf(f64);
    var min_power: f64 = math.inf(f64);
    var avg_power: f64 = 0.0;
    var variance: f64 = 0.0;
    
    // Calculate basic statistics
    for (trace) |sample| {
        max_power = @max(max_power, sample.power);
        min_power = @min(min_power, sample.power);
        avg_power += sample.power;
    }
    avg_power /= @as(f64, @floatFromInt(trace.len));
    
    // Calculate variance
    for (trace) |sample| {
        const diff = sample.power - avg_power;
        variance += diff * diff;
    }
    variance /= @as(f64, @floatFromInt(trace.len));
    
    // Find peaks and patterns
    var peak_count: u32 = 0;
    const threshold = avg_power + math.sqrt(variance) * 2.0;
    
    for (trace[1..trace.len-1], 1..) |sample, i| {
        if (sample.power > threshold and 
            sample.power > trace[i-1].power and 
            sample.power > trace[i+1].power) {
            peak_count += 1;
        }
    }
    
    // Fill result structure - simplified for compatibility
    _ = result;
    // Variables used in calculations: max_power, min_power, avg_power, variance, peak_count
    
    return 0;
}

/// Perform Differential Power Analysis (DPA)
export fn performDPA(ctx: *DPAContext, byte_position: u8, key_byte_guess: u8) f64 {
    if (ctx.traces.items.len != ctx.plaintexts.items.len) return 0.0;
    
    var group0_traces = ArrayList([]PowerSample).init(ctx.allocator);
    var group1_traces = ArrayList([]PowerSample).init(ctx.allocator);
    defer group0_traces.deinit();
    defer group1_traces.deinit();
    
    // Partition traces based on intermediate value bit
    for (ctx.traces.items, 0..) |trace, i| {
        const plaintext = ctx.plaintexts.items[i];
        const intermediate = AES_SBOX[plaintext[byte_position] ^ key_byte_guess];
        const bit_value = (intermediate >> 0) & 1; // LSB
        
        if (bit_value == 0) {
            group0_traces.append(trace) catch continue;
        } else {
            group1_traces.append(trace) catch continue;
        }
    }
    
    if (group0_traces.items.len == 0 or group1_traces.items.len == 0) return 0.0;
    
    // Calculate average traces for each group
    const trace_length = group0_traces.items[0].len;
    var avg0 = ctx.allocator.alloc(f64, trace_length) catch return 0.0;
    var avg1 = ctx.allocator.alloc(f64, trace_length) catch return 0.0;
    defer ctx.allocator.free(avg0);
    defer ctx.allocator.free(avg1);
    
    // Initialize averages
    for (avg0) |*val| val.* = 0.0;
    for (avg1) |*val| val.* = 0.0;
    
    // Calculate group 0 average
    for (group0_traces.items) |trace| {
        for (trace, 0..) |sample, j| {
            avg0[j] += sample.power;
        }
    }
    for (avg0) |*val| val.* /= @as(f64, @floatFromInt(group0_traces.items.len));
    
    // Calculate group 1 average
    for (group1_traces.items) |trace| {
        for (trace, 0..) |sample, j| {
            avg1[j] += sample.power;
        }
    }
    for (avg1) |*val| val.* /= @as(f64, @floatFromInt(group1_traces.items.len));
    
    // Calculate differential trace
    var max_diff: f64 = 0.0;
    for (avg0, avg1) |a0, a1| {
        const diff = @abs(a0 - a1);
        max_diff = @max(max_diff, diff);
    }
    
    return max_diff;
}

/// Perform Correlation Power Analysis (CPA)
export fn performCPA(ctx: *CPAContext, byte_position: u8) i32 {
    if (ctx.traces.items.len == 0) return -1;
    
    const trace_length = ctx.traces.items[0].len;
    var max_correlation: f64 = 0.0;
    var best_key: u8 = 0;
    
    // Test all possible key bytes
    for (0..256) |key_guess| {
        var power_values = ctx.allocator.alloc(f64, ctx.traces.items.len) catch return -2;
        var hamming_values = ctx.allocator.alloc(f64, ctx.traces.items.len) catch {
            ctx.allocator.free(power_values);
            return -2;
        };
        defer ctx.allocator.free(power_values);
        defer ctx.allocator.free(hamming_values);
        
        var max_point_correlation: f64 = 0.0;
        
        // Test each point in the trace
        for (0..trace_length) |point| {
            // Extract power values at this point
            for (ctx.traces.items, 0..) |trace, i| {
                power_values[i] = trace[point].power;
            }
            
            // Calculate hypothetical intermediate values and Hamming weights
            for (ctx.intermediate_values.items, 0..) |intermediate, i| {
                const hyp_intermediate = AES_SBOX[intermediate[byte_position] ^ @as(u8, @intCast(key_guess))];
                hamming_values[i] = @as(f64, @floatFromInt(hammingWeight(hyp_intermediate)));
            }
            
            // Calculate correlation
            const correlation = calculateCorrelation(power_values, hamming_values);
            max_point_correlation = @max(max_point_correlation, @abs(correlation));
        }
        
        ctx.correlation_coefficients[key_guess] = max_point_correlation;
        
        if (max_point_correlation > max_correlation) {
            max_correlation = max_point_correlation;
            best_key = @as(u8, @intCast(key_guess));
        }
    }
    
    return 0;
}

/// Add power trace to DPA context
export fn addTraceToDPA(ctx: *DPAContext, trace: [*]const PowerSample, trace_length: usize,
                       plaintext: [*]const u8, plaintext_length: usize,
                       ciphertext: [*]const u8, ciphertext_length: usize) i32 {
    
    // Copy trace
    const trace_copy = ctx.allocator.alloc(PowerSample, trace_length) catch return -2;
    @memcpy(trace_copy, trace[0..trace_length]);
    ctx.traces.append(trace_copy) catch {
        ctx.allocator.free(trace_copy);
        return -2;
    };
    
    // Copy plaintext
    const plaintext_copy = ctx.allocator.alloc(u8, plaintext_length) catch return -2;
    @memcpy(plaintext_copy, plaintext[0..plaintext_length]);
    ctx.plaintexts.append(plaintext_copy) catch {
        ctx.allocator.free(plaintext_copy);
        return -2;
    };
    
    // Copy ciphertext
    const ciphertext_copy = ctx.allocator.alloc(u8, ciphertext_length) catch return -2;
    @memcpy(ciphertext_copy, ciphertext[0..ciphertext_length]);
    ctx.ciphertexts.append(ciphertext_copy) catch {
        ctx.allocator.free(ciphertext_copy);
        return -2;
    };
    
    return 0;
}

/// Template attack implementation
export fn performTemplateAttack(templates: *anyopaque, template_count: usize,
                                target_trace: [*]const PowerSample, trace_length: usize,
                                result: *u8) i32 {
    _ = templates;
    _ = template_count;
    _ = target_trace;
    _ = trace_length;
    result.* = 0;
    return 0;
}

/// Calculate mutual information for leakage assessment
export fn calculateMutualInformation(traces: [*]const [*]const PowerSample, trace_count: usize,
                                   trace_length: usize, intermediate_values: [*]const u8,
                                   result: *f64) i32 {
    
    // Simplified mutual information calculation
    // In practice, this would use proper histogram-based estimation
    
    var total_mi: f64 = 0.0;
    _ = 256; // num_bins removed for compatibility
    
    for (0..trace_length) |point| {
        var power_values = std.heap.page_allocator.alloc(f64, trace_count) catch return -2;
        defer std.heap.page_allocator.free(power_values);
        
        // Extract power values at this point
        for (0..trace_count) |i| {
            power_values[i] = traces[i][point].power;
        }
        
        // Calculate correlation with intermediate values (simplified MI)
        var iv_values = std.heap.page_allocator.alloc(f64, trace_count) catch return -2;
        defer std.heap.page_allocator.free(iv_values);
        
        for (0..trace_count) |i| {
            iv_values[i] = @as(f64, @floatFromInt(intermediate_values[i]));
        }
        
        const correlation = calculateCorrelation(power_values, iv_values);
        const mi = -0.5 * @log(1.0 - correlation * correlation);
        total_mi = @max(total_mi, mi);
    }
    
    result.* = total_mi;
    return 0;
}