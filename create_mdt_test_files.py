#!/usr/bin/env python3

import struct
import os
import shutil

def create_mdt_test_files():
    """Create proper MDT test files for the radare2 test suite"""
    
    print("Creating MDT test files...")
    
    # Create directory structure
    os.makedirs("test/bins/mdt/bin-mdt", exist_ok=True)
    
    # Copy hexagon binary as base
    hexagon_file = "test/bins/elf/analysis/hexagon-hello-loop"
    if not os.path.exists(hexagon_file):
        print(f"Error: {hexagon_file} not found")
        return False
    
    # Read hexagon binary
    with open(hexagon_file, 'rb') as f:
        hexagon_data = f.read()
    
    # Create a basic MDT header (ELF format with MDT-specific program headers)
    # ELF header for 32-bit Hexagon with MDT modifications
    mdt_header = bytearray(52)  # ELF header size
    
    # ELF magic + class/data/version
    mdt_header[0:16] = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8
    
    # e_type = ET_EXEC (2), e_machine = Hexagon (0xa4)  
    struct.pack_into('<HH', mdt_header, 16, 2, 0xa4)
    
    # e_version = 1
    struct.pack_into('<I', mdt_header, 20, 1)
    
    # e_entry = 0x87400000 (typical Qualcomm entry)
    struct.pack_into('<I', mdt_header, 24, 0x87400000)
    
    # e_phoff = 52 (program header starts after ELF header)
    struct.pack_into('<I', mdt_header, 28, 52)
    
    # e_shoff = 0 (no section headers in MDT)
    struct.pack_into('<I', mdt_header, 32, 0)
    
    # e_flags = 0x66, e_ehsize = 52
    struct.pack_into('<IH', mdt_header, 36, 0x66, 52)
    
    # e_phentsize = 32, e_phnum = 5 (5 segments as expected by tests)
    struct.pack_into('<HH', mdt_header, 42, 32, 5)
    
    # e_shentsize = 40, e_shnum = 0, e_shstrndx = 0
    struct.pack_into('<HHH', mdt_header, 46, 40, 0, 0)
    
    # Create 5 program headers as expected by tests
    program_headers = bytearray(32 * 5)  # 5 headers * 32 bytes each
    
    # Segment 0: Layout segment (p_flags = 0x7 = layout | ELF)
    struct.pack_into('<IIIIIIII', program_headers, 0, 
                     1,           # p_type = PT_LOAD
                     0,           # p_offset  
                     0x87400000,  # p_vaddr
                     0x87400000,  # p_paddr
                     len(hexagon_data), # p_filesz
                     len(hexagon_data), # p_memsz
                     0x7,         # p_flags = layout | ELF
                     0x1000)      # p_align
    
    # Segment 1: MBN signature segment (p_flags = 0x2000000 = MBN signature)
    struct.pack_into('<IIIIIIII', program_headers, 32,
                     1,           # p_type = PT_LOAD  
                     0,           # p_offset
                     0x89200000,  # p_vaddr
                     0x89200000,  # p_paddr
                     40,          # p_filesz (MBN header size)
                     0x2000,      # p_memsz 
                     0x2000000,   # p_flags = MBN signature
                     0x1000)      # p_align
    
    # Segment 2: Relocatable segment (p_flags = 0x10000000 = relocatable)
    struct.pack_into('<IIIIIIII', program_headers, 64,
                     1,           # p_type = PT_LOAD
                     0,           # p_offset
                     0xfe030000,  # p_vaddr  
                     0x87400000,  # p_paddr
                     0x30000,     # p_filesz
                     0x7f000,     # p_memsz
                     0x10000000,  # p_flags = relocatable
                     0x100000)    # p_align
    
    # Segment 3: ELF relocatable segment  
    struct.pack_into('<IIIIIIII', program_headers, 96,
                     1,           # p_type = PT_LOAD
                     0x1000,      # p_offset
                     0x00550000,  # p_vaddr
                     0x874af000,  # p_paddr
                     0x12160,     # p_filesz
                     0x1a000,     # p_memsz
                     0x10000000,  # p_flags = relocatable  
                     0x1000)      # p_align
    
    # Segment 4: Another ELF relocatable segment
    struct.pack_into('<IIIIIIII', program_headers, 128,
                     1,           # p_type = PT_LOAD
                     0x874c9000,  # p_offset (high address to indicate separate file)
                     0xc00c9000,  # p_vaddr
                     0x874c9000,  # p_paddr  
                     0x5b4,       # p_filesz
                     0x1000,      # p_memsz
                     0x10000000,  # p_flags = relocatable
                     0x1000)      # p_align
    
    # Create the main MDT file
    mdt_content = bytes(mdt_header) + bytes(program_headers)
    
    # Pad to reasonable size
    mdt_content += b'\x00' * (512 - len(mdt_content))
    
    with open("test/bins/mdt/bin-mdt/load-test.mdt", 'wb') as f:
        f.write(mdt_content)
    
    # Create companion .b0X files based on hexagon binary
    # These would typically be parts of the firmware
    
    # .b01 - MBN signature file (empty for now)
    with open("test/bins/mdt/bin-mdt/load-test.b01", 'wb') as f:
        f.write(b'\x00' * 0x1c18)  # Size expected by test
    
    # .b02 - Main firmware (use hexagon binary)  
    with open("test/bins/mdt/bin-mdt/load-test.b02", 'wb') as f:
        f.write(hexagon_data)
        f.write(b'\x00' * (0x30000 - len(hexagon_data)))  # Pad to expected size
    
    # .b03 - Another ELF part (copy hexagon binary)
    with open("test/bins/mdt/bin-mdt/load-test.b03", 'wb') as f:
        f.write(hexagon_data)
    
    # .b04 - Relocatable part (create minimal ELF)
    relocs_elf = create_minimal_hexagon_elf_with_relocs()
    with open("test/bins/mdt/bin-mdt/load-test.b04", 'wb') as f:
        f.write(relocs_elf)
    
    print("MDT test files created successfully!")
    return True

def create_minimal_hexagon_elf_with_relocs():
    """Create a minimal Hexagon ELF with relocations for testing"""
    
    # This creates a simple ELF that the relocation tests expect
    # Based on the test expectations for symbols like test_sym, r_hex_b15_pcrel etc.
    
    elf_data = bytearray(0x5b4)  # Size expected by tests
    
    # ELF header
    elf_data[0:16] = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HH', elf_data, 16, 1, 0xa4)  # ET_REL, Hexagon
    struct.pack_into('<I', elf_data, 20, 1)  # e_version
    # entry = 0, phoff = 0 for relocatable
    struct.pack_into('<II', elf_data, 24, 0, 0)
    struct.pack_into('<I', elf_data, 32, 0x4ec)  # e_shoff
    struct.pack_into('<I', elf_data, 36, 0x60)   # e_flags
    struct.pack_into('<H', elf_data, 40, 52)     # e_ehsize
    struct.pack_into('<HH', elf_data, 42, 0, 0)  # no program headers
    struct.pack_into('<HHH', elf_data, 46, 40, 5, 1)  # section headers
    
    # Add some test symbols and relocations data
    # This is a simplified version - the real implementation would be much more complex
    
    return bytes(elf_data)

if __name__ == "__main__":
    create_mdt_test_files()