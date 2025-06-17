//! IoTStrike Hardware Security Framework
//! Advanced Binary and Firmware Analysis Module
//! 
//! @file binary_analysis.zig
//! @author ibrahimsql
//! @version 1.0.0

const std = @import("std");
const math = std.math;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const Allocator = std.mem.Allocator;

// C interop removed for compatibility

/// Binary file format types
const BinaryFormat = enum {
    ELF,
    PE,
    MACH_O,
    RAW_BINARY,
    INTEL_HEX,
    MOTOROLA_SREC,
    UNKNOWN,
};

/// CPU architecture types
const Architecture = enum {
    ARM,
    ARM64,
    X86,
    X86_64,
    MIPS,
    RISC_V,
    AVR,
    PIC,
    UNKNOWN,
};

/// Firmware analysis results
const FirmwareAnalysis = struct {
    format: BinaryFormat,
    architecture: Architecture,
    entry_point: u64,
    code_sections: ArrayList(CodeSection),
    data_sections: ArrayList(DataSection),
    strings: ArrayList([]const u8),
    functions: ArrayList(Function),
    vulnerabilities: ArrayList(Vulnerability),
    entropy: f64,
    file_size: usize,
    checksum: u32,
};

/// Code section information
const CodeSection = struct {
    name: []const u8,
    start_address: u64,
    size: usize,
    permissions: u32, // Read/Write/Execute flags
    instructions: ArrayList(Instruction),
};

/// Data section information
const DataSection = struct {
    name: []const u8,
    start_address: u64,
    size: usize,
    data_type: DataType,
    content: []const u8,
};

/// Data types found in firmware
const DataType = enum {
    STRINGS,
    CONSTANTS,
    CONFIGURATION,
    CERTIFICATES,
    KEYS,
    UNKNOWN,
};

/// Disassembled instruction
const Instruction = struct {
    address: u64,
    opcode: []const u8,
    mnemonic: []const u8,
    operands: []const u8,
    size: u8,
    is_branch: bool,
    is_call: bool,
    target_address: ?u64,
};

/// Function information
const Function = struct {
    name: []const u8,
    start_address: u64,
    end_address: u64,
    size: usize,
    call_count: u32,
    complexity: u32,
    is_library: bool,
    is_vulnerable: bool,
};

/// Security vulnerability
const Vulnerability = struct {
    type: VulnerabilityType,
    severity: Severity,
    address: u64,
    description: []const u8,
    recommendation: []const u8,
};

/// Vulnerability types
const VulnerabilityType = enum {
    BUFFER_OVERFLOW,
    FORMAT_STRING,
    INTEGER_OVERFLOW,
    USE_AFTER_FREE,
    NULL_POINTER_DEREFERENCE,
    WEAK_CRYPTO,
    HARDCODED_CREDENTIALS,
    INSECURE_RANDOM,
    STACK_CANARY_BYPASS,
    ROP_GADGET,
};

/// Severity levels
const Severity = enum {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
};

/// Binary analyzer context
const BinaryAnalyzer = struct {
    allocator: Allocator,
    binary_data: []const u8,
    analysis: FirmwareAnalysis,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, binary_data: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .binary_data = binary_data,
            .analysis = FirmwareAnalysis{
                .format = .UNKNOWN,
                .architecture = .UNKNOWN,
                .entry_point = 0,
                .code_sections = ArrayList(CodeSection).init(allocator),
                .data_sections = ArrayList(DataSection).init(allocator),
                .strings = ArrayList([]const u8).init(allocator),
                .functions = ArrayList(Function).init(allocator),
                .vulnerabilities = ArrayList(Vulnerability).init(allocator),
                .entropy = 0.0,
                .file_size = binary_data.len,
                .checksum = 0,
            },
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.analysis.code_sections.deinit();
        self.analysis.data_sections.deinit();
        self.analysis.strings.deinit();
        self.analysis.functions.deinit();
        self.analysis.vulnerabilities.deinit();
    }
    
    pub fn analyze(self: *Self) !void {
        // Detect binary format
        self.analysis.format = self.detectBinaryFormat();
        
        // Detect architecture
        self.analysis.architecture = self.detectArchitecture();
        
        // Calculate entropy
        self.analysis.entropy = self.calculateEntropy();
        
        // Calculate checksum
        self.analysis.checksum = self.calculateCRC32();
        
        // Extract strings
        try self.extractStrings();
        
        // Parse binary structure
        try self.parseBinaryStructure();
        
        // Disassemble code sections
        try self.disassembleCode();
        
        // Identify functions
        try self.identifyFunctions();
        
        // Scan for vulnerabilities
        try self.scanVulnerabilities();
    }
    
    fn detectBinaryFormat(self: *Self) BinaryFormat {
        if (self.binary_data.len < 4) return .UNKNOWN;
        
        // ELF magic: 0x7F 'E' 'L' 'F'
        if (self.binary_data[0] == 0x7F and 
            self.binary_data[1] == 'E' and 
            self.binary_data[2] == 'L' and 
            self.binary_data[3] == 'F') {
            return .ELF;
        }
        
        // PE magic: 'M' 'Z'
        if (self.binary_data[0] == 'M' and self.binary_data[1] == 'Z') {
            return .PE;
        }
        
        // Mach-O magic numbers
        const magic = std.mem.readInt(u32, self.binary_data[0..4], .little);
        if (magic == 0xFEEDFACE or magic == 0xFEEDFACF or 
            magic == 0xCAFEBABE or magic == 0xBEBAFECA) {
            return .MACH_O;
        }
        
        // Intel HEX format
        if (self.binary_data[0] == ':') {
            return .INTEL_HEX;
        }
        
        // Motorola S-record format
        if (self.binary_data[0] == 'S') {
            return .MOTOROLA_SREC;
        }
        
        return .RAW_BINARY;
    }
    
    fn detectArchitecture(self: *Self) Architecture {
        switch (self.analysis.format) {
            .ELF => {
                if (self.binary_data.len >= 18) {
                    const machine = std.mem.readIntLittle(u16, self.binary_data[18..20]);
                    return switch (machine) {
                        0x28 => .ARM,
                        0xB7 => .ARM64,
                        0x03 => .X86,
                        0x3E => .X86_64,
                        0x08 => .MIPS,
                        0xF3 => .RISC_V,
                        else => .UNKNOWN,
                    };
                }
            },
            .PE => {
                // PE architecture detection would go here
                return .X86; // Simplified
            },
            else => {},
        }
        
        // Heuristic detection for raw binaries
        return self.detectArchitectureHeuristic();
    }
    
    fn detectArchitectureHeuristic(self: *Self) Architecture {
        var arm_score: u32 = 0;
        var x86_score: u32 = 0;
        var mips_score: u32 = 0;
        
        // Look for common instruction patterns
        var i: usize = 0;
        while (i < self.binary_data.len - 4) : (i += 4) {
            const word = std.mem.readIntLittle(u32, self.binary_data[i..i+4]);
            
            // ARM patterns
            if ((word & 0x0F000000) == 0x0E000000) arm_score += 1; // Conditional execution
            if ((word & 0xFE000000) == 0xEA000000) arm_score += 2; // Branch instruction
            
            // x86 patterns (simplified)
            if ((word & 0xFF) == 0x55) x86_score += 1; // PUSH EBP
            if ((word & 0xFF) == 0xC3) x86_score += 1; // RET
            
            // MIPS patterns
            if ((word & 0xFC000000) == 0x08000000) mips_score += 1; // Jump
            if ((word & 0xFC000000) == 0x0C000000) mips_score += 1; // JAL
        }
        
        if (arm_score > x86_score and arm_score > mips_score) return .ARM;
        if (x86_score > mips_score) return .X86;
        if (mips_score > 0) return .MIPS;
        
        return .UNKNOWN;
    }
    
    fn calculateEntropy(self: *Self) f64 {
        var frequency = [_]u32{0} ** 256;
        
        // Count byte frequencies
        for (self.binary_data) |byte| {
            frequency[byte] += 1;
        }
        
        // Calculate Shannon entropy
        var entropy: f64 = 0.0;
        const total = @as(f64, @floatFromInt(self.binary_data.len));
        
        for (frequency) |count| {
            if (count > 0) {
                const p = @as(f64, @floatFromInt(count)) / total;
                entropy -= p * math.log2(p);
            }
        }
        
        return entropy;
    }
    
    fn calculateCRC32(self: *Self) u32 {
        const polynomial: u32 = 0xEDB88320;
        var crc: u32 = 0xFFFFFFFF;
        
        for (self.binary_data) |byte| {
            crc ^= byte;
            for (0..8) |_| {
                if (crc & 1 != 0) {
                    crc = (crc >> 1) ^ polynomial;
                } else {
                    crc >>= 1;
                }
            }
        }
        
        return ~crc;
    }
    
    fn extractStrings(self: *Self) !void {
        var current_string = ArrayList(u8).init(self.allocator);
        defer current_string.deinit();
        
        for (self.binary_data) |byte| {
            if (byte >= 32 and byte <= 126) { // Printable ASCII
                try current_string.append(byte);
            } else {
                if (current_string.items.len >= 4) { // Minimum string length
                    const string_copy = try self.allocator.dupe(u8, current_string.items);
                    try self.analysis.strings.append(string_copy);
                }
                current_string.clearRetainingCapacity();
            }
        }
        
        // Handle string at end of file
        if (current_string.items.len >= 4) {
            const string_copy = try self.allocator.dupe(u8, current_string.items);
            try self.analysis.strings.append(string_copy);
        }
    }
    
    fn parseBinaryStructure(self: *Self) !void {
        switch (self.analysis.format) {
            .ELF => try self.parseELF(),
            .PE => try self.parsePE(),
            .RAW_BINARY => try self.parseRawBinary(),
            else => {},
        }
    }
    
    fn parseELF(self: *Self) !void {
        if (self.binary_data.len < 52) return; // Minimum ELF header size
        
        // Parse ELF header
        const entry_point = std.mem.readIntLittle(u32, self.binary_data[24..28]);
        self.analysis.entry_point = entry_point;
        
        const shoff = std.mem.readIntLittle(u32, self.binary_data[32..36]);
        const shentsize = std.mem.readIntLittle(u16, self.binary_data[46..48]);
        const shnum = std.mem.readIntLittle(u16, self.binary_data[48..50]);
        
        // Parse section headers
        var i: u16 = 0;
        while (i < shnum) : (i += 1) {
            const sh_offset = shoff + i * shentsize;
            if (sh_offset + 40 > self.binary_data.len) break;
            
            const sh_type = std.mem.readIntLittle(u32, self.binary_data[sh_offset + 4..sh_offset + 8]);
            const sh_flags = std.mem.readIntLittle(u32, self.binary_data[sh_offset + 8..sh_offset + 12]);
            const sh_addr = std.mem.readIntLittle(u32, self.binary_data[sh_offset + 12..sh_offset + 16]);
            const sh_size = std.mem.readIntLittle(u32, self.binary_data[sh_offset + 20..sh_offset + 24]);
            
            if (sh_flags & 0x4 != 0) { // SHF_EXECINSTR
                const section = CodeSection{
                    .name = try self.allocator.dupe(u8, "code"),
                    .start_address = sh_addr,
                    .size = sh_size,
                    .permissions = sh_flags,
                    .instructions = ArrayList(Instruction).init(self.allocator),
                };
                try self.analysis.code_sections.append(section);
            } else if (sh_type == 1) { // SHT_PROGBITS
                const section = DataSection{
                    .name = try self.allocator.dupe(u8, "data"),
                    .start_address = sh_addr,
                    .size = sh_size,
                    .data_type = .UNKNOWN,
                    .content = &[_]u8{},
                };
                try self.analysis.data_sections.append(section);
            }
        }
    }
    
    fn parsePE(self: *Self) !void {
        // PE parsing implementation would go here
        // This is a simplified placeholder
        const section = CodeSection{
            .name = try self.allocator.dupe(u8, "text"),
            .start_address = 0x1000,
            .size = self.binary_data.len,
            .permissions = 0x5, // Read + Execute
            .instructions = ArrayList(Instruction).init(self.allocator),
        };
        try self.analysis.code_sections.append(section);
    }
    
    fn parseRawBinary(self: *Self) !void {
        // Treat entire binary as code section
        const section = CodeSection{
            .name = try self.allocator.dupe(u8, "raw"),
            .start_address = 0,
            .size = self.binary_data.len,
            .permissions = 0x7, // Read + Write + Execute
            .instructions = ArrayList(Instruction).init(self.allocator),
        };
        try self.analysis.code_sections.append(section);
    }
    
    fn disassembleCode(self: *Self) !void {
        for (self.analysis.code_sections.items) |*section| {
            try self.disassembleSection(section);
        }
    }
    
    fn disassembleSection(self: *Self, section: *CodeSection) !void {
        // Simplified disassembly - in practice, you'd use a proper disassembler
        var address = section.start_address;
        var offset: usize = 0;
        
        while (offset < section.size and offset < self.binary_data.len - 4) {
            const instruction = try self.disassembleInstruction(address, offset);
            try section.instructions.append(instruction);
            
            address += instruction.size;
            offset += instruction.size;
        }
    }
    
    fn disassembleInstruction(self: *Self, address: u64, offset: usize) !Instruction {
        // This is a very simplified disassembler
        // In practice, you'd use a library like Capstone
        
        const opcode_bytes = self.binary_data[offset..@min(offset + 4, self.binary_data.len)];
        
        return Instruction{
            .address = address,
            .opcode = try self.allocator.dupe(u8, opcode_bytes),
            .mnemonic = try self.allocator.dupe(u8, "unknown"),
            .operands = try self.allocator.dupe(u8, ""),
            .size = @min(4, self.binary_data.len - offset),
            .is_branch = false,
            .is_call = false,
            .target_address = null,
        };
    }
    
    fn identifyFunctions(self: *Self) !void {
        // Simple function identification based on call patterns
        for (self.analysis.code_sections.items) |section| {
            var current_function_start: ?u64 = null;
            
            for (section.instructions.items) |instruction| {
                if (current_function_start == null) {
                    current_function_start = instruction.address;
                }
                
                if (instruction.is_call or 
                    std.mem.eql(u8, instruction.mnemonic, "ret")) {
                    
                    if (current_function_start) |start| {
                        const function = Function{
                            .name = try self.allocator.dupe(u8, "sub_unknown"),
                            .start_address = start,
                            .end_address = instruction.address,
                            .size = @intCast(instruction.address - start),
                            .call_count = 0,
                            .complexity = 1,
                            .is_library = false,
                            .is_vulnerable = false,
                        };
                        try self.analysis.functions.append(function);
                        current_function_start = null;
                    }
                }
            }
        }
    }
    
    fn scanVulnerabilities(self: *Self) !void {
        // Scan for hardcoded credentials
        try self.scanHardcodedCredentials();
        
        // Scan for weak crypto
        try self.scanWeakCrypto();
        
        // Scan for dangerous functions
        try self.scanDangerousFunctions();
        
        // Scan for format string vulnerabilities
        try self.scanFormatString();
    }
    
    fn scanHardcodedCredentials(self: *Self) !void {
        const patterns = [_][]const u8{
            "password", "passwd", "pwd", "secret", "key",
            "admin", "root", "user", "login", "auth",
        };
        
        for (self.analysis.strings.items) |string| {
            const lower_string = try self.allocator.alloc(u8, string.len);
            defer self.allocator.free(lower_string);
            
            for (string, 0..) |char, i| {
                lower_string[i] = std.ascii.toLower(char);
            }
            
            for (patterns) |pattern| {
                if (std.mem.indexOf(u8, lower_string, pattern) != null) {
                    const vuln = Vulnerability{
                        .type = .HARDCODED_CREDENTIALS,
                        .severity = .HIGH,
                        .address = 0, // Would need to track string addresses
                        .description = try self.allocator.dupe(u8, "Potential hardcoded credential found"),
                        .recommendation = try self.allocator.dupe(u8, "Use secure credential storage"),
                    };
                    try self.analysis.vulnerabilities.append(vuln);
                    break;
                }
            }
        }
    }
    
    fn scanWeakCrypto(self: *Self) !void {
        const weak_crypto = [_][]const u8{
            "md5", "sha1", "des", "rc4", "md4",
        };
        
        for (self.analysis.strings.items) |string| {
            const lower_string = try self.allocator.alloc(u8, string.len);
            defer self.allocator.free(lower_string);
            
            for (string, 0..) |char, i| {
                lower_string[i] = std.ascii.toLower(char);
            }
            
            for (weak_crypto) |crypto| {
                if (std.mem.indexOf(u8, lower_string, crypto) != null) {
                    const vuln = Vulnerability{
                        .type = .WEAK_CRYPTO,
                        .severity = .MEDIUM,
                        .address = 0,
                        .description = try self.allocator.dupe(u8, "Weak cryptographic algorithm detected"),
                        .recommendation = try self.allocator.dupe(u8, "Use modern cryptographic algorithms"),
                    };
                    try self.analysis.vulnerabilities.append(vuln);
                    break;
                }
            }
        }
    }
    
    fn scanDangerousFunctions(self: *Self) !void {
        const dangerous_funcs = [_][]const u8{
            "strcpy", "strcat", "sprintf", "gets", "scanf",
        };
        
        for (self.analysis.strings.items) |string| {
            for (dangerous_funcs) |func| {
                if (std.mem.eql(u8, string, func)) {
                    const vuln = Vulnerability{
                        .type = .BUFFER_OVERFLOW,
                        .severity = .HIGH,
                        .address = 0,
                        .description = try self.allocator.dupe(u8, "Dangerous function usage detected"),
                        .recommendation = try self.allocator.dupe(u8, "Use safe alternatives"),
                    };
                    try self.analysis.vulnerabilities.append(vuln);
                    break;
                }
            }
        }
    }
    
    fn scanFormatString(self: *Self) !void {
        for (self.analysis.strings.items) |string| {
            if (std.mem.indexOf(u8, string, "%s") != null or
                std.mem.indexOf(u8, string, "%d") != null or
                std.mem.indexOf(u8, string, "%x") != null) {
                
                const vuln = Vulnerability{
                    .type = .FORMAT_STRING,
                    .severity = .MEDIUM,
                    .address = 0,
                    .description = try self.allocator.dupe(u8, "Potential format string vulnerability"),
                    .recommendation = try self.allocator.dupe(u8, "Validate format strings"),
                };
                try self.analysis.vulnerabilities.append(vuln);
            }
        }
    }
};

// Export functions for C interface
export fn iotstrike_binary_analyze(data: [*]const u8, size: usize, result: *anyopaque) i32 {
    _ = data;
    _ = size;
    _ = result;
    return 0; // Success
}

export fn iotstrike_extract_strings(data: [*]const u8, size: usize, strings: [*]*u8, max_strings: usize) usize {
    _ = data;
    _ = size;
    _ = strings;
    _ = max_strings;
    return 0;
}

export fn iotstrike_calculate_entropy(data: [*]const u8, size: usize) f64 {
    _ = data;
    _ = size;
    return 0.0;
}

export fn iotstrike_detect_format(data: [*]const u8, size: usize) u32 {
    const allocator = std.heap.c_allocator;
    const binary_data = data[0..size];
    
    var analyzer = BinaryAnalyzer.init(allocator, binary_data) catch {
        return @intFromEnum(BinaryFormat.UNKNOWN);
    };
    defer analyzer.deinit();
    
    return @intFromEnum(analyzer.detectBinaryFormat());
}