#!/usr/bin/env python3
"""
OpenVMS Executable Format Analyzer
Analyzes VAX and Alpha VMS executable files to understand their structure
"""

import struct
import sys
from pathlib import Path


class VMSExecutable:
    """Base class for VMS executable analysis"""
    
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self.arch = None
        self.header = {}
        
    def detect_architecture(self):
        """Detect if this is VAX or Alpha based on magic bytes"""
        if len(self.data) < 4:
            return None
            
        # VAX format: starts with 0xB0 0x00
        if self.data[0] == 0xB0 and self.data[1] == 0x00:
            return 'VAX'
        
        # Alpha format: starts with 0x03 0x00 0x00 0x00
        if self.data[0] == 0x03 and self.data[1] == 0x00:
            return 'ALPHA'
            
        return None
    
    def hexdump(self, offset, length, label=""):
        """Display hex dump of a region"""
        if label:
            print(f"\n{label}:")
        
        for i in range(0, length, 16):
            addr = offset + i
            chunk = self.data[addr:addr+16]
            
            # Hex part
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(48)  # 16 bytes * 3 chars
            
            # ASCII part
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            print(f"{addr:08x}  {hex_part}  |{ascii_part}|")
    
    def read_string_at(self, offset, max_len=256):
        """Read a null-terminated or length-prefixed string"""
        if offset >= len(self.data):
            return ""
        
        # Check if it's a length-prefixed string (Pascal-style)
        length = self.data[offset]
        if length > 0 and length < max_len:
            if offset + 1 + length <= len(self.data):
                try:
                    return self.data[offset+1:offset+1+length].decode('ascii', errors='ignore')
                except:
                    pass
        
        # Try null-terminated string
        end = offset
        while end < len(self.data) and end < offset + max_len:
            if self.data[end] == 0:
                break
            end += 1
        
        try:
            return self.data[offset:end].decode('ascii', errors='ignore')
        except:
            return ""
    
    def find_strings(self, min_len=4):
        """Find printable ASCII strings in the binary"""
        strings = []
        current = ""
        offset = 0
        
        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:
                if not current:
                    offset = i
                current += chr(byte)
            else:
                if len(current) >= min_len:
                    strings.append((offset, current))
                current = ""
        
        return strings


class VAXExecutable(VMSExecutable):
    """VAX VMS executable parser"""
    
    def parse_header(self):
        """Parse VAX EIHD (Executable Image Header)"""
        print("\n" + "="*60)
        print("VAX VMS EXECUTABLE ANALYSIS")
        print("="*60)
        
        # Display first 512 bytes
        self.hexdump(0, 512, "Raw Header Data (first 512 bytes)")
        
        # Parse EIHD structure (based on observation)
        if len(self.data) < 176:  # Minimum header size
            print("\nFile too small to contain valid header")
            return
        
        print("\n" + "-"*60)
        print("EIHD (Executable Image Header) Analysis")
        print("-"*60)
        
        # Parse known fields
        majorid = struct.unpack('<H', self.data[0:2])[0]
        minorid = struct.unpack('<H', self.data[2:4])[0]
        eihd_size = struct.unpack('<H', self.data[4:6])[0]
        isdoff = struct.unpack('<H', self.data[6:8])[0]
        
        print(f"Major ID:           0x{majorid:04x} ({majorid})")
        print(f"Minor ID:           0x{minorid:04x} ({minorid})")
        print(f"EIHD Size:          0x{eihd_size:04x} ({eihd_size} bytes)")
        print(f"ISD Offset:         0x{isdoff:04x} ({isdoff})")
        
        # Look for image name (usually around offset 0x60-0x70)
        print("\n" + "-"*60)
        print("Image Information")
        print("-"*60)
        
        # Image name at offset 0x60
        if len(self.data) > 0x70:
            img_name_len = self.data[0x60]
            if img_name_len > 0 and img_name_len < 32:
                img_name = self.data[0x61:0x61+img_name_len].decode('ascii', errors='ignore')
                print(f"Image Name:         {img_name}")
        
        # Version at offset 0x80
        if len(self.data) > 0x90:
            ver_len = self.data[0x80]
            if ver_len > 0 and ver_len < 32:
                version = self.data[0x81:0x81+ver_len].decode('ascii', errors='ignore')
                print(f"Version:            {version}")
        
        # VMS version at offset 0xA0
        if len(self.data) > 0xB0:
            vms_ver_len = self.data[0xA0]
            if vms_ver_len > 0 and vms_ver_len < 32:
                vms_version = self.data[0xA1:0xA1+vms_ver_len].decode('ascii', errors='ignore')
                print(f"VMS Version:        {vms_version}")
        
        # Parse Image Section Descriptors (ISD) if offset is valid
        if isdoff > 0 and isdoff < len(self.data):
            print("\n" + "-"*60)
            print(f"Image Section Descriptors at offset 0x{isdoff:04x}")
            print("-"*60)
            self.hexdump(isdoff, min(256, len(self.data) - isdoff), "ISD Data")
            self.parse_isds(isdoff)
        
        # Find shared library references
        self.find_shared_libraries()
    
    def parse_isds(self, offset):
        """Parse Image Section Descriptors"""
        print("\nParsing ISDs:")
        current = offset
        isd_num = 0
        
        while current < len(self.data) - 16:
            # ISD appears to be 16 bytes based on pattern
            isd_data = self.data[current:current+16]
            
            # Check for terminator (all 0xFF)
            if isd_data == b'\xff' * 16:
                print(f"  ISD {isd_num}: TERMINATOR")
                break
            
            # Try to parse ISD structure
            size = struct.unpack('<H', isd_data[0:2])[0]
            if size == 0 or size > 0x1000:  # Sanity check
                break
                
            flags = struct.unpack('<H', isd_data[2:4])[0]
            vbn = struct.unpack('<I', isd_data[4:8])[0]
            
            print(f"  ISD {isd_num}: size=0x{size:04x}, flags=0x{flags:04x}, vbn=0x{vbn:08x}")
            
            current += 16
            isd_num += 1
            
            if isd_num > 20:  # Safety limit
                break
    
    def find_shared_libraries(self):
        """Find shared library references in the executable"""
        print("\n" + "-"*60)
        print("Shared Library References")
        print("-"*60)
        
        # Look for common VMS library patterns
        strings = self.find_strings(min_len=8)
        
        lib_keywords = ['SHR', 'RTL', 'LIB', 'DECW$', 'CMA$', 'DECC$', 'VAX']
        
        for offset, string in strings:
            if any(kw in string.upper() for kw in lib_keywords):
                if '$' in string or '_' in string:  # VMS library naming convention
                    print(f"  0x{offset:08x}: {string}")


class AlphaExecutable(VMSExecutable):
    """Alpha VMS executable parser"""
    
    def parse_header(self):
        """Parse Alpha EIHD (Executable Image Header)"""
        print("\n" + "="*60)
        print("ALPHA VMS EXECUTABLE ANALYSIS")
        print("="*60)
        
        # Display first 512 bytes
        self.hexdump(0, 512, "Raw Header Data (first 512 bytes)")
        
        if len(self.data) < 256:
            print("\nFile too small to contain valid header")
            return
        
        print("\n" + "-"*60)
        print("EIHD (Executable Image Header) Analysis")
        print("-"*60)
        
        # Parse known fields (32-bit for Alpha)
        majorid = struct.unpack('<I', self.data[0:4])[0]
        minorid = struct.unpack('<I', self.data[4:8])[0]
        eihd_size = struct.unpack('<I', self.data[8:12])[0]
        
        print(f"Major ID:           0x{majorid:08x} ({majorid})")
        print(f"Minor ID:           0x{minorid:08x} ({minorid})")
        print(f"EIHD Size:          0x{eihd_size:08x} ({eihd_size} bytes)")
        
        # Look for image name
        print("\n" + "-"*60)
        print("Image Information")
        print("-"*60)
        
        # Image name appears around 0xC0-0xD0
        if len(self.data) > 0xD0:
            img_name_len = self.data[0xC4]
            if img_name_len > 0 and img_name_len < 32:
                img_name = self.data[0xC5:0xC5+img_name_len].decode('ascii', errors='ignore')
                print(f"Image Name:         {img_name}")
        
        # Version at offset 0xF0
        if len(self.data) > 0x100:
            ver_len = self.data[0xF0]
            if ver_len > 0 and ver_len < 32:
                version = self.data[0xF1:0xF1+ver_len].decode('ascii', errors='ignore')
                print(f"Version:            {version}")
        
        # Alpha version identifier at offset 0x100
        if len(self.data) > 0x110:
            alpha_ver_len = self.data[0x100]
            if alpha_ver_len > 0 and alpha_ver_len < 32:
                alpha_version = self.data[0x101:0x101+alpha_ver_len].decode('ascii', errors='ignore')
                print(f"Alpha Version:      {alpha_version}")
        
        # Find Image Section Descriptors
        print("\n" + "-"*60)
        print("Image Section Descriptors")
        print("-"*60)
        self.parse_isds()
        
        # Find shared library references
        self.find_shared_libraries()
    
    def parse_isds(self):
        """Parse Alpha Image Section Descriptors"""
        # ISDs appear to start around 0x120 based on the pattern
        offset = 0x120
        isd_num = 0
        
        print("\nParsing ISDs:")
        
        while offset < len(self.data) - 36:
            isd_data = self.data[offset:offset+36]
            
            # Check for terminator
            if isd_data[:16] == b'\xff' * 16:
                print(f"  ISD {isd_num}: TERMINATOR")
                break
            
            # Alpha ISDs appear to be larger (36+ bytes)
            size = struct.unpack('<I', isd_data[0:4])[0]
            flags = struct.unpack('<I', isd_data[4:8])[0]
            
            if size == 0 or size == 0xFFFFFFFF:
                break
            
            print(f"  ISD {isd_num}: size=0x{size:08x}, flags=0x{flags:08x}")
            
            offset += 36
            isd_num += 1
            
            if isd_num > 20:
                break
    
    def find_shared_libraries(self):
        """Find shared library references"""
        print("\n" + "-"*60)
        print("Shared Library References")
        print("-"*60)
        
        strings = self.find_strings(min_len=8)
        
        lib_keywords = ['SHR', 'RTL', 'LIB', 'DECW$', 'CMA$', 'DECC$', 'LIBRTL']
        
        for offset, string in strings:
            if any(kw in string.upper() for kw in lib_keywords):
                if '$' in string or '_' in string:
                    print(f"  0x{offset:08x}: {string}")


def analyze_vms_executable(filepath):
    """Main analysis function"""
    print(f"\nAnalyzing: {filepath}")
    print("="*60)
    
    vms = VMSExecutable(filepath)
    arch = vms.detect_architecture()
    
    if arch is None:
        print("ERROR: Unable to detect VMS executable format")
        print("This may not be a VMS VAX or Alpha executable")
        return
    
    print(f"Detected Architecture: {arch}")
    
    if arch == 'VAX':
        analyzer = VAXExecutable(filepath)
        analyzer.parse_header()
    elif arch == 'ALPHA':
        analyzer = AlphaExecutable(filepath)
        analyzer.parse_header()
    
    print("\n" + "="*60)
    print("Analysis Complete")
    print("="*60)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vms_analyzer.py <vms_executable>")
        print("\nExample:")
        print("  python3 vms_analyzer.py links-2.30-vax.exe")
        print("  python3 vms_analyzer.py links-2.30-alpha.exe")
        sys.exit(1)
    
    for filepath in sys.argv[1:]:
        analyze_vms_executable(filepath)
        print("\n")


if __name__ == "__main__":
    main()