import abc
import textwrap
import hashlib
import time
import mmap
from prodids import vs_version, int_names

banner_text = """
  /$$$$$$ /$$   /$$/$$   /$$ /$$$$$$ /$$/$$$$$$         /$$$$$$ /$$$$$$$$/$$$$$$ /$$$$$$$$/$$$$$$ /$$$$$$         /$$$$$$ /$$   /$$ /$$$$$$ /$$  /$$     /$$/$$$$$$ /$$$$$$ /$$$$$$ 
 /$$__  $| $$  | $| $$  | $$/$$__  $| $/$$__  $$       /$$__  $|__  $$__/$$__  $|__  $$__|_  $$_//$$__  $$       /$$__  $| $$$ | $$/$$__  $| $$ |  $$   /$$/$$__  $|_  $$_//$$__  $$
| $$  \__| $$  | $| $$  | $| $$  \ $|_| $$  \__/      | $$  \__/  | $$ | $$  \ $$  | $$    | $$ | $$  \__/      | $$  \ $| $$$$| $| $$  \ $| $$  \  $$ /$$| $$  \__/ | $$ | $$  \__/
|  $$$$$$| $$$$$$$| $$  | $| $$$$$$$$ |  $$$$$$       |  $$$$$$   | $$ | $$$$$$$$  | $$    | $$ | $$            | $$$$$$$| $$ $$ $| $$$$$$$| $$   \  $$$$/|  $$$$$$  | $$ |  $$$$$$ 
 \____  $| $$__  $| $$  | $| $$__  $$  \____  $$       \____  $$  | $$ | $$__  $$  | $$    | $$ | $$            | $$__  $| $$  $$$| $$__  $| $$    \  $$/  \____  $$ | $$  \____  $$
 /$$  \ $| $$  | $| $$  | $| $$  | $$  /$$  \ $$       /$$  \ $$  | $$ | $$  | $$  | $$    | $$ | $$    $$      | $$  | $| $$\  $$| $$  | $| $$     | $$   /$$  \ $$ | $$  /$$  \ $$
|  $$$$$$| $$  | $|  $$$$$$| $$  | $$ |  $$$$$$/      |  $$$$$$/  | $$ | $$  | $$  | $$   /$$$$$|  $$$$$$/      | $$  | $| $$ \  $| $$  | $| $$$$$$$| $$  |  $$$$$$//$$$$$|  $$$$$$/
 \______/|__/  |__/\______/|__/  |__/  \______/        \______/   |__/ |__/  |__/  |__/  |______/\______/       |__/  |__|__/  \__|__/  |__|________|__/   \______/|______/\______/ 
"""
"""
To Do: Create optional32 header fields, use random and ansi escape sequences to colorize output. Also tabulate
Create methods for returning the necessary information from each header to parse other headers/set vars etc
"""


class Header():

    byte_dict = {'word': 2, 'dword': 4, 'qword': 8, 'long': 4, 'tword': 20, 
                 'ulonglong': 8, 'byte': 8, 'custom_sha256': 32, 'bit': 1}

    def __init__(self,fields_dict, file_to_open, start_bytes, end_bytes):
        self.fields_dict = fields_dict
        self.file_to_open = file_to_open
        self.start_bytes = start_bytes
        self.end_bytes = end_bytes

    def reverse_endianness(self, data):
        if type(data) == str:
            byte_data = bytearray.fromhex(data)
            byte_data.reverse()
            return byte_data
        else:
            convert_to_string = str(data)
            byte_data = bytearray.fromhex(convert_to_string)
            byte_data.reverse()
            return byte_data

    def time_date_stamp_stomp(self, time_date_stamp):
        tds = self.reverse_endianness(time_date_stamp).hex()
        formatted_tds = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(tds, 16)))
        return formatted_tds

    def parse(self):
        current_marker = self.start_bytes
        return_values_dict = {}
        for k,v in self.fields_dict.items():
            with open(self.file_to_open, 'rb') as f:
                contents = f.read()
                return_values_tmp = contents[current_marker: current_marker + self.byte_dict[v]].hex()
                if k == 'TimeDateStamp':
                    return_values_dict[k] = self.time_date_stamp_stomp(return_values_tmp)
                    current_marker += self.byte_dict[v]
                else:
                    return_values_dict[k] = self.reverse_endianness(return_values_tmp).hex()
                    current_marker += self.byte_dict[v]
        return_values_dict['current_marker'] = current_marker
        return return_values_dict

    def is_64_bit(self, machine_type):
        if machine_type == '8664':
            return True
        else:
            return False

    def pretty_print(self, return_values_dict):
        special_keys = ('Name')
        for k,v in return_values_dict.items():
            if k in special_keys:
                field_temp_value = self.reverse_endianness(str(v)).hex()
                print(bytearray.fromhex(field_temp_value).decode())
            else:
                print(k + " : " + str(v))

    
        

class Rich_header(Header):

    def __init__(self,fields_dict, user_file):
        self.user_file = user_file
        self.fields_dict = fields_dict

    def find_rich_header(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            bits = '52696368'
        return contents.find(bytes.fromhex(bits))

    def find_rich_checksum(self, signature_location):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            start_marker = int(signature_location)  + 4
            stop_marker = start_marker + 4
            checksum = contents[start_marker:stop_marker].hex()
        return checksum 

    def find_comp_ids(self, signature_location):
        with open(self.user_file, 'rb') as f:
            comp_ids = []
            contents = f.read()
            start_marker = int(signature_location) - 8
            stop_marker = int(signature_location)
            checksum_value = self.find_rich_checksum(signature_location)
        while ( 
            str(contents[start_marker:start_marker+4].hex()) != str(checksum_value) 
            and str(contents[start_marker+4:stop_marker]) != str(checksum_value)):
            test_value = contents[start_marker:stop_marker].hex()
            comp_ids.append(test_value)
            stop_marker = start_marker
            start_marker = start_marker - 8
        return comp_ids

    def xor(self, data, key):
        return bytearray( ((data[i] ^ key[i % len(key)]) for i in range(0, len(data))))

    def decode_component_ids(self):
        location = self.find_rich_header()
        comp_ids = self.find_comp_ids(location)
        chksum = self.find_rich_checksum(location)
        decoded = []
        products = []
        for product in comp_ids:
            data = bytearray.fromhex(product)
            key = bytearray.fromhex(chksum)
            decoded.append(self.xor(data, key).hex())
        for value in decoded:
            products.append(value)  
        return products

    def reverse_endianness(self, products_list):
        corrected_list = []
        for _ in range(len(products_list)):
            corrected_list.append(super().reverse_endianness(products_list[_]).hex())
        return corrected_list

    def product_matching(self, corrected_list):
        final_product_list = []
        for product in corrected_list:
            field_1 = product[:8]
            field_2 = product[8:]
            product_id = '0x' + str(field_2[:4])
            version = vs_version(int(product_id, 16))
            build_id = field_2[4:]
            count = field_1
            prod_tuple = (version, int_names[product_id], int(build_id, 16), int(count, 16))
            final_product_list.append(prod_tuple)
        return final_product_list

class Dos_stub(Header):

    def __init__(self, fields_dict, file_to_open, start_bytes, end_bytes):
        self.fields_dict = fields_dict
        self.user_file = file_to_open
        self.start_bytes = start_bytes
        self.end_bytes = end_bytes
        

    def is_dos_modified(self):
        with open(self.user_file, 'rb') as f:
            modified = False
            contents = f.read()
            dos_stub_contents = contents[self.start_bytes:self.end_bytes].hex()
            stub_hash = "cdd075d13ab03486f5a0382ab4bccf1eb2c985b2064808f5099eb4cf334d391a"
            stub_encoding = dos_stub_contents.encode('utf-8')
            current_stub_hash = hashlib.sha256(stub_encoding)
            if current_stub_hash.hexdigest() != stub_hash:
                modified = True
            return modified
            
            
dos_header_fields = {'e_magic':'word', 'e_cblp':'word', 'e_cp':'word', 
              'e_crlc':'word', 'e_cparhdr':'word', 'e_minalloc':'word',
              'e_maxalloc':'word', 'e_ss':'word', 'e_sp':'word',
              'e_csum':'word', 'e_ip':'word', 'e_cs':'word',
              'e_lfarlc':'word', 'e_ovno':'word', 'e_res4':'qword',
              'e_oemid':'word', 'e_oeminfo':'word', 'e_res10':'tword',
              'e_lfanew':'long'}

rich_header_fields = {'dans': 'dword', 'checksum_padding1': 'dword',
                      'checksum_padding2': 'dword', 
                      'checksum_padding3': 'dword',
                      'comp_ids': [],
                      'rich_signature': 'dword',
                      'checksum': 'dword'
                      }

nt_header_fields = {'signature': 'dword', 'machine': 'word', 
                    'NumberOfSections': 'word', 'TimeDateStamp': 'dword',
                    'PointerToSymbolTable': 'dword', 
                    'NumberOfSymbols': 'dword', 'SizeOfOptionalHeader': 'word',
                    'Characteristics': 'word' }

optional64_section_header_fields = {'magic': 'word', 
                                    'MajorLinkerVersion': 'bit',
                                    'MinorLinkerVersion': 'bit',
                                    'SizeOfCode': 'dword',
                                    'SizeOfInitializedData': 'dword',
                                    'SizeOfUninitData': 'dword',
                                    'AddressOfEntryPoint': 'dword',
                                    'BaseOfCode': 'dword', 
                                    'ImageBase': 'ulonglong', 
                                    'SectionAlignment': 'dword',
                                    'FileAlignment': 'dword', 
                                    'MajorOsSystemVersion': 'word',
                                    'MinorOsSystemVersion': 'word',
                                    'MajorImageVersion': 'word',
                                    'MinorImageVersion': 'word',
                                    'MajorSubsystemVersion': 'word',
                                    'MinorSubsystemVersion': 'word',
                                    'Win32VersionValue': 'dword',
                                    'SizeOfImage': 'dword', 
                                    'SizeOfHeaders': 'dword', 
                                    'checksum': 'dword', 'subsystem': 'word',
                                    'dllCharacteristics': 'word', 
                                    'SizeOfStackReserve': 'ulonglong',
                                    'SizeOfStackCommit': 'ulonglong',
                                    'SizeOfHeapReserve': 'ulonglong',
                                    'SizeOfHeapCommit': 'ulonglong',
                                    'loaderFlags': 'dword', 
                                    'NumberOfRvaAndSizes': 'dword',
                                    'ExportDirectoryAddress': 'dword',
                                    'ExportDirectorySize': 'dword',
                                    'ImportDirectoryAddress': 'dword',
                                    'ImportDirectorySize': 'dword',
                                    'ResourceDirectoryAddress': 'dword',
                                    'ResourceDirectorySize': 'dword',
                                    'ExceptionDirectoryAddress': 'dword',
                                    'ExceptionDirectorySize': 'dword',
                                    'SecurityDirectoryAddress': 'dword',
                                    'SecurityDirectorySize': 'dword',
                                    'BaseRelocationTableAddress': 'dword',
                                    'BaseRelocationTableSize': 'dword',
                                    'DebugDirectoryAddress': 'dword',
                                    'DebugDirectorySize': 'dword',
                                    'ArchitectureSpecificAddress': 'dword',
                                    'ArchitectureSpecificSize': 'dword',
                                    'RVAofGPAddress': 'dword',
                                    'RVAofGPSize': 'dword',
                                    'tlsDirectoryAddress': 'dword',
                                    'tlsDirectorySize': 'dword',
                                    'loadConfigurationDirectory': 'dword',
                                    'loadConfigurationSize': 'dword',
                                    'boundImportDirectory': 'dword',
                                    'boundImportSize': 'dword', 
                                    'importAddressTableAddress': 'dword',
                                    'importAddressTableSize': 'dword',
                                    'delayLoadImportAddress': 'dword',
                                    'delayLoadImportSize': 'dword',
                                    'comRuntimeAddress': 'dword',
                                    'comRuntimeSize': 'dword'}

optional_32_header_fields = {'Magic': 'word', 'MajorLinkerVersion': 'byte',
                             'MinorLinkerVersion': 'byte', 
                             'SizeOfCode': 'dword',
                             'SizeOfInitializedData': 'dword', 
                             'SizeOfUninitializedData': 'dword', 
                             'AddressOfEntryPoint': 'dword', 
                             'BaseOfCode': 'dword', 'BaseOfData': 'dword',
                             'ImageBase': 'dword', 
                             'SectionAlignment': 'dword',
                             'FileAlignment': 'dword',
                             'MajorOperatingSystemVersion': 'word',
                             'MinorOperatingSystemVersion': 'word',
                             'MajorImageversion': 'word', 
                             'MinorImageVersion': 'word',
                             'MajorSubsystemVersion': 'word',
                             'MinorSubsystemVersion': 'word',
                             'Win32VersionsValue': 'dword',
                             'SizeOfImage': 'dword', 
                             'SizeOfHeaders': 'dword', 'checksum': 'dword',
                             'Subsystem': 'word', 
                             'DLLCharacteristics': 'word',
                             'SizeOfStackReserve': 'dword', 
                             'SizeOfStackCommit': 'dword',
                             'SizeOfHeapReserve': 'dword',
                             'SizeOfHeapCommit': 'dword',
                             'LoaderFlags': 'dword',
                             'NumberOfRvaAmdSizes': 'dword'}


section_header_fields = {'Name': 'byte', 'virtualSize': 'dword', 
                         'virtualAddress': 'dword', 'sizeOfRawData': 'dword',
                         'pointerToRawData': 'dword', 
                         'pointerToRelocations': 'dword',
                         'pointerToLineNumbers': 'dword', 
                         'NumberOfRelocations': 'word', 
                         'NumberOfLineNumbers': 'word',
                         'characteristics': 'dword'}

dos_stub_header_fields = {'Hash': 'custom_sha256' }

