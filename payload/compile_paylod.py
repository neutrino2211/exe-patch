import sys

def bytes_to_c_byte_array(byte_data):
    # Format each byte as a hexadecimal value
    byte_array = ', '.join(f'0x{byte:02X}' for byte in byte_data)
    # Format the result as a C-style array
    c_byte_array = f'BYTE* __RAW_EXE_DATA__ = &{{ {byte_array} }};'
    return c_byte_array

# Example usage
byte_data = b'\x01\x02\x03\x04\xFF'
c_code = bytes_to_c_byte_array(byte_data)
print(c_code)

with open("clean-dir/raw_exe.hpp", "w") as output:
    out_code = bytes_to_c_byte_array(open(sys.argv[1], 'rb').read())
    output.write(out_code)

    print(out_code)