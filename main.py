#!/usr/bin/env python3

import struct
import sys
import json
import urllib.request
from pathlib import Path


def find_bun_section(data, pe_offset):
    """
    Locate .bun section in PE executable.
    
    Args:
        data (bytes): Raw executable data
        pe_offset (int): PE header offset location
    
    Returns:
        tuple: (start_offset, size) or (None, None) if not found
    """
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    optional_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    section_table_offset = pe_offset + 24 + optional_header_size
    
    for i in range(num_sections):
        section_offset = section_table_offset + (i * 40)
        section_name = data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        
        if section_name == '.bun':
            virtual_size = struct.unpack('<I', data[section_offset+8:section_offset+12])[0]
            raw_size = struct.unpack('<I', data[section_offset+16:section_offset+20])[0]
            raw_offset = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]
            return raw_offset, min(virtual_size, raw_size)
    
    return None, None


def find_js_boundary(bundle, chunk_size=1000, threshold=0.3):
    """
    Detect where JavaScript ends and binary data begins.
    
    Args:
        bundle (bytes): JavaScript bundle data
        chunk_size (int): Size of chunks to analyze
        threshold (float): Non-printable ratio threshold
    
    Returns:
        int: Offset where binary data starts
    """
    for i in range(0, min(len(bundle), 50_000_000), chunk_size):
        chunk = bundle[i:i+chunk_size]
        if not chunk:
            break
        
        non_printable = sum(1 for b in chunk if b > 127 or (b < 32 and b not in [9, 10, 13]))
        ratio = non_printable / len(chunk)
        
        if ratio > threshold:
            return i
    
    return len(bundle)


def refine_boundary(bundle, initial_end):
    """
    Refine JavaScript boundary by detecting end markers.
    
    Args:
        bundle (bytes): JavaScript bundle data
        initial_end (int): Initial boundary offset
    
    Returns:
        int: Refined boundary offset
    """
    next_data = bundle[initial_end:initial_end+2000]
    ascii_count = sum(1 for b in next_data[:500] if 32 <= b < 127)
    
    if ascii_count <= 50:
        return initial_end
    
    markers = [b'//# debugId=', b'//# sourceMappingURL=', b'})();']
    
    for marker in markers:
        marker_pos = next_data.find(marker)
        if marker_pos >= 0:
            line_end = next_data.find(b'\n', marker_pos)
            if line_end >= 0:
                check_after = next_data[line_end+1:line_end+101]
                if len(check_after) > 0:
                    binary_ratio = sum(1 for b in check_after if b > 127 or (b < 32 and b not in [9,10,13])) / len(check_after)
                    if binary_ratio > 0.4:
                        return initial_end + line_end + 1
    
    for i in range(min(1000, len(next_data))):
        byte = next_data[i]
        if byte in [ord(';'), ord('}'), ord(')')]:
            check_ahead = next_data[i+1:i+101]
            if len(check_ahead) > 0:
                binary_ratio = sum(1 for b in check_ahead if b > 127 or (b < 32 and b not in [9,10,13])) / len(check_ahead)
                if binary_ratio > 0.5:
                    return initial_end + i + 1
    
    return initial_end


def extract_bun_js(version):
    url = f'https://downloads.claude.ai/claude-code-releases/{version}/win32-x64/claude.exe'

    with urllib.request.urlopen(url) as response:
        data = response.read()
    
    js_start = None
    
    if data[0:2] == b'MZ':
        pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
        if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
            js_start, _ = find_bun_section(data, pe_offset)
    
    if js_start is None:
        magic = b'\xe5\x02\x80\x01'
        pos = data.find(magic)
        if pos != -1:
            js_start = pos
    
    if js_start is None:
        print("Error: Could not locate JavaScript bundle")
        return False
    
    bundle = data[js_start:]
    js_marker_pos = bundle.find(b'// @bun')
    
    if js_marker_pos == -1:
        print("Error: Could not find JavaScript marker")
        return False
    
    bundle = bundle[js_marker_pos:]
    initial_end = find_js_boundary(bundle)
    final_end = refine_boundary(bundle, initial_end)
    js_data = bundle[:final_end]
    
    try:
        js_code = js_data.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error: Decoding failed: {e}")
        return False
    
    output_file = f"claude-code-{version}.js"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(js_code)
    
    print(f"Extracted: {output_file}")
    print(f"Size: {len(js_code):,} bytes")
    
    return True


def main():

    latest_url = "https://registry.npmjs.org/@anthropic-ai/claude-code/latest"

    with urllib.request.urlopen(latest_url) as response:
        data = json.load(response)

    version = data["version"]

    if Path(f"claude-code-{version}.js").exists():
        return
    
    if not extract_bun_js(version):
        sys.exit(1)


if __name__ == "__main__":
    main()
