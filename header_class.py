import abc
import textwrap
import hashlib
import time
from prodids import vs_version, int_names

class Header(abc.ABC):
    
    @classmethod
    def print_information(self, input):
        pass

    @classmethod
    def parse(self):
        pass

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

class Dos_header(Header):

    def __init__(self, file_to_open, start_bytes, end_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes
        self.end_bytes = end_bytes

    # Overide print_information class method
    def print_information(self,provided_input):
        signature = provided_input[0]
        e_cblp = provided_input[1]
        e_cp = provided_input[2]
        e_crlc = provided_input[3]
        e_cparhdr = provided_input[4]
        e_minalloc = provided_input[5]
        e_maxalloc = provided_input[6]
        e_ss = provided_input[7]
        e_sp = provided_input[8]
        e_csum = provided_input[9]
        e_ip = provided_input[10]
        e_cs = provided_input[11]
        e_lfarlc = provided_input[12]
        e_ovno = provided_input[13]
        e_res = provided_input[14]
        e_oemid = provided_input[15]
        e_oeminfo = provided_input[16]
        e_res2 = provided_input[17]
        e_lfanew = provided_input[18]
        print( 'Signature: ' + str(signature) + '\n' + 
            'Bytes on last page: ' + str(e_cblp) + '\n' + 
            'Pages in file: ' + str(e_cp) + '\n' + 
            'Relocations: ' + str(e_crlc) + '\n' + 
            'Size of header in paragraphs: ' + str(e_cparhdr) + '\n' +
            'Minimum extra paragraphs needed: ' + str(e_minalloc) + '\n' +
            'Maximum extra paragraphs needed: ' + str(e_maxalloc) + '\n' +  
            'Initial (relative) SS value: ' + str(e_ss) + '\n' + 
            'Initial SP value: ' + str(e_sp) + '\n' + 
            'Checksum: ' + str(e_csum) + '\n' + 
            'Initial IP value: ' + str(e_ip) + '\n' + 
            'Initial (relative) CS value: ' + str(e_cs) + '\n' + 
            'File address relocation table: ' + str(e_lfarlc) + '\n' + 
            'Overlay Number: ' + str(e_ovno) + '\n' + 
            'Reserved Words Array[4]: ' + str(e_res) + '\n' + 
            'OEM identifier (for e_oeminfo): ' + str(e_oemid) + '\n' + 
            'OEM information; e_oemid specific: ' + str(e_oeminfo) + '\n' +
            'Reserved Words Array[10]: ' + str(e_res2) + '\n' +
            'File address of new exe header: ' + str(e_lfanew) + '\n')

    # Override parse class method
    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            signature = contents[0:2].hex()
            if signature != '4d5a':
                print("Invalid Signature")
            e_cblp = contents[2:4].hex()
            e_cp = contents[4:6].hex()
            e_crlc = contents[6:8].hex()
            e_cparhdr = contents[8:10].hex()
            e_minalloc = contents[10:12].hex()
            e_maxalloc = contents[12:14].hex()
            e_ss = contents[14:16].hex()
            e_sp = contents[16:18].hex()
            e_csum = contents[18:20].hex()
            e_ip = contents[20:22].hex()
            e_cs = contents[22:24].hex()
            e_lfarlc = contents[24:26].hex()
            e_ovno = contents[26:28].hex()
            e_res = contents[28:35].hex()
            e_oemid = contents[35:37].hex()
            e_oeminfo = contents[37:39].hex()
            e_res2 = contents[39:60].hex()
            e_lfanew = contents[60:64].hex()
        
            if e_cblp[2:] == "00":
                e_cblp = e_cblp[:2]

            if e_cp[2:] == "00":
                e_cp = e_cp[:2]

            if e_crlc[2:] == "00":
                e_crlc = e_crlc[:2]
            
            if e_cparhdr[2:] == "00":
                e_cparhdr = e_cparhdr[:2]

            if e_minalloc[2:] == "00":
                e_minalloc = e_minalloc[:2]
            
            if e_maxalloc[2:] == "00":
                e_maxalloc = e_maxalloc[:2]
            
            if e_ss[2:] == "00":
                e_ss = e_ss[:2]
            
            if e_sp[2:] == "00":
                e_sp = e_sp[:2]

            if e_csum[2:] == "00":
                e_csum = e_csum[:2]

            if e_ip[2:] == "00":
                e_ip = e_ip[:2]
            
            if e_cs[2:] == "00":
                e_cs = e_cs[:2]

            if e_lfarlc[2:] == "00":
                e_lfarlc = e_lfarlc[:2]

            if e_ovno[2:] == "00":
                e_ovno = e_ovno[:2]
            
            res_array = []
            _ = 0
            while _ < len(e_res):
                res_array.append(str(int(e_res[_:_+4])))
                _ += 4
            
            if e_oemid[2:] == "00":
                e_oemid = e_oemid[:2]

            if e_oeminfo[2:] == "00":
                e_oeminfo = e_oeminfo[:2]
            
            res2_array = []
            _ = 0
            while _ < len(e_res2):
                res2_array.append(str(int(e_res2[_:_+4], 16)))
                _ += 4


            if e_lfanew[6:] == "00":
                e_lfanew = str(int(e_lfanew[:2], 16))

        file_info_tuple = (signature, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc,
                        e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, 
                        e_ovno, res_array, e_oemid, e_oeminfo, res2_array, e_lfanew)
    
        return file_info_tuple


class Rich_header(Header):

    def __init__(self, file_to_open, start_bytes, end_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes
        self.end_bytes = end_bytes

    def xor(self, data, key):
        return bytearray( ((data[i] ^ key[i % len(key)]) for i in range(0, len(data))))
    
    # Overide parse
    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            rich_header = contents[128:224]
            dans = contents[128:132].hex()
            checksum_padding_1 = contents[132:136].hex()
            checksum_padding_2 = contents[136:140].hex()
            checksum_padding_3 = contents[140:144].hex()
            comp_id_1 = contents[144:152].hex()
            comp_id_2 = contents[152:160].hex()
            comp_id_3 = contents[160:168].hex()
            comp_id_4 = contents[168:176].hex()
            comp_id_5 = contents[176:184].hex()
            comp_id_6 = contents[184:192].hex()
            comp_id_7 = contents[192:200].hex()
            comp_id_8 = contents[200:208].hex()
            comp_id_9 = contents[208:216].hex()
            rich_id = contents[216:220].hex()
            checksum = contents[220:224].hex()
            rich_header_hex = rich_header.hex()
            data = bytearray.fromhex(rich_header_hex)


            key = bytearray.fromhex(checksum)

            rch_hdr = (self.xor(data, key)).hex()
            rch_hdr = textwrap.wrap(rch_hdr, 16)

            products = []
            for i in range(2, len(rch_hdr)):
                tmp = textwrap.wrap(rch_hdr[i], 8)
                f1 = super().reverse_endianness(tmp[0])
                f2 = super().reverse_endianness(tmp[1])
                f1_hexed = f1.hex()
                f1_sliced = f1_hexed[0:4]
                f1_fnibble_str = "0x" + str(f1_sliced)
                try:
                    version = vs_version(int(f1_fnibble_str, 16))
                    product = int_names[f1_fnibble_str]
                    product_tuple = (str(product), str(version), str(int(f1_hexed[4:], 16)), str(int(f2.hex(), 16)))
                    products.append(product_tuple)
                except KeyError:
                    pass
            return products
        
    # Override print_information
    def print_information(self, products_list):
        for product in products_list:
            product_id = product[0]
            returned_version = product[1]
            version_build = product[2]
            version_count = product[3]
            print('Product Id: ' + str(product_id) + '\n' +
                 'VS Version: ' + str(returned_version) + '\n' +
                 'Build Id: ' + str(version_build) + '\n' +
                 'Count: ' + str(version_count) + '\n' )

class Stub_header(Header):

    def __init__(self, file_to_open, start_bytes, end_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes
        self.end_bytes = end_bytes
    
    # Overide Parse
    def parse(self):
        with open(self.user_file, 'rb') as f:
            modified_stub = False
            contents = f.read()
            dos_stub = contents[64:128].hex()
            stub_hash = "cdd075d13ab03486f5a0382ab4bccf1eb2c985b2064808f5099eb4cf334d391a"
            encoded_string = dos_stub.encode('utf-8')
            dos_stub_hash = hashlib.sha256(encoded_string)
            if dos_stub_hash.hexdigest() != stub_hash:
                modified_stub = True
            return modified_stub
    
    # Overide Print Information
    def print_information(self, stub_results):
        modified_stub = stub_results
        if modified_stub:
            print("The stub has been modified!" + '\n')
        else:
            print("Normal DOS STUB nothing to see here" + '\n')


class NT_headers(Header):

    def __init__(self, file_to_open, start_bytes, end_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes
        self.end_bytes = end_bytes

    def check_mach_type(self, machine_type):
        machine_type = super().reverse_endianness(machine_type)
        return machine_type.hex()

    def is_64_bit(self, machine_type):
        if machine_type == '8664':
            return True
        else:
            return False


    def human_readable_time(self, time_date_stamp):
        tds = super().reverse_endianness(time_date_stamp)
        formatted_tds = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(tds.hex(), 16)))
        return formatted_tds

    def num_of_sections(self, section_number):
        number_of_sections = super().reverse_endianness(section_number)
        return number_of_sections.hex()

    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            header_marker = self.begin_bytes
            nt_header_end = header_marker + 64
            # NT HEADER SIGNATURE IS 4 BYTES
            nt_header_signature = contents[header_marker:header_marker + 4].hex()
            header_marker += 4
            if (nt_header_signature[:4]) != "5045":
                print("Invalid NT header signature")
                exit()
            # After signature is IMAGE FILE HEADER/COFF HEADER AND IS 20 BYTES
            # Within image file header, we have 20 bytes of values
            # Machine is a word/2BYTES
            machine_type = contents[header_marker:header_marker + 2].hex()
            machine_type = self.check_mach_type(machine_type)
            header_marker += 2
            # Number of Sections is word/2BYTES
            number_of_sections = contents[header_marker:header_marker + 2].hex()
            number_of_sections = self.num_of_sections(number_of_sections)
            header_marker += 2
            # Time date stamp is UNIX EPOCH DWORD/4BYTES
            # TODO reverse endianness and convert to readable date time
            time_date_stamp = contents[header_marker:header_marker + 4].hex()
            header_marker += 4
            time_date_stamp = self.human_readable_time(time_date_stamp)
            # PTR to symbol table is DWORD/4BYTES
            pointer_to_symbole_table = contents[header_marker:header_marker + 4].hex()
            header_marker += 4
            # Number of symbols is DWORD/4BYTES
            number_of_symbols = contents[header_marker:header_marker + 4].hex()
            header_marker += 4
            # Size of optional header is word/2BYTES
            size_of_optional_header = contents[header_marker:header_marker + 2].hex()
            header_marker += 2
            if size_of_optional_header[2:] == "00":
                size_of_optional_header = int(size_of_optional_header[:2], 16)
            # Characteristics is word/2BYTES
            image_file_header_characteristics = contents[header_marker:header_marker + 2].hex()
            header_marker += 2
            is_64_bool = self.is_64_bit(machine_type)
            nt_header_info = (nt_header_signature, machine_type, 
                            number_of_sections, time_date_stamp,
                            pointer_to_symbole_table, number_of_symbols,
                            size_of_optional_header, image_file_header_characteristics, header_marker, is_64_bool)
            return nt_header_info


    # Override print information
    def print_information(self, nt_header_info):
        nt_signature = nt_header_info[0]
        nt_machine_type = nt_header_info[1]
        nt_amount_sections = nt_header_info[2]
        nt_tds = nt_header_info[3]
        nt_ptr_symbol = nt_header_info[4]
        nt_num_syboles = nt_header_info[5]
        nt_size_of_optional = nt_header_info[6]
        nt_image_characteristics = nt_header_info[7]
        header_marker = nt_header_info[8]
        bit_size = nt_header_info[9]
        print("NT SIGNATURE: " + str(nt_signature[:4]) + '\n' +
              "NT Machine Type: " + str(nt_machine_type) + '\n' +
              "NT Number of Sections: " + str(int(nt_amount_sections, 16)) + '\n' +
              "Time Date Stampe: " + str(nt_tds) + '\n' +
              "NT Pointer to Symbol Table: " + str(int(nt_ptr_symbol, 16)) + '\n' +
              "NT Number of Symbols: " + str(int(nt_num_syboles, 16)) + '\n' +
              "NT Size of Optional Header: " + str(nt_size_of_optional) + '\n' +
              "NT Image Characteristics: " + str(nt_image_characteristics) + '\n' +
              "Header Marker: " + str(header_marker) + '\n' +
              "Is 64 bit: " + str(bit_size) + '\n')


class Optional_header(Header):

    def __init__(self, file_to_open, start_bytes, end_bytes, bit_bool):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes
        self.end_bytes = end_bytes
        self.bit_size = bit_bool

    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            marker = self.begin_bytes
            # Standard Fields
            # Magic is a word 2bytes
            optional_magic = contents[marker:marker + 2].hex()
            marker += 2
            # Major and Minor linker version are 1 byte each
            major_linker_version = contents[marker:marker + 1].hex()
            marker += 1
            minor_linker_version = contents[marker:marker + 1].hex()
            marker += 1
            # Size of code is a Dword/4bytes
            size_of_code = contents[marker:marker + 4].hex()
            marker +=4
            # Size of init data is dword
            size_of_initialized_data = contents[marker:marker + 4].hex()
            marker += 4
            # Size of Uninit data is dword
            size_of_uninit_data = contents[marker:marker + 4].hex()
            marker += 4
            # Address of Entry point is dword
            address_of_entry_point = contents[marker: marker + 4].hex()
            marker += 4
            # Base of Code dword
            base_of_code = contents[marker: marker + 4 ].hex()
            marker += 4
            deets_tuple = (optional_magic, major_linker_version, 
                           minor_linker_version, size_of_code, 
                           size_of_initialized_data, size_of_uninit_data,
                           address_of_entry_point, base_of_code, marker, self.bit_size)
            
            return deets_tuple

class Optional64_header(Header):

    def __init__(self, file_to_open, start_bytes):
        self.user_file = file_to_open
        self.start_bytes = start_bytes

    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            # First Field in 64 header is ulonglong/8bytes!
            image_base = contents[int(self.start_bytes):int(self.start_bytes) + 8].hex()
            marker = int(self.start_bytes) + 8
            # Section Alignment DWORD
            section_alignment = contents[marker: marker + 4].hex()
            marker += 4
            # File Alignment DWORD
            file_alignment = contents[marker: marker + 4].hex()
            marker += 4
            # Major Operating system version word
            major_os_sys_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor OS version word
            minor_os_sys_version = contents[marker: marker + 2].hex()
            marker += 2
            # Major image version word
            major_image_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor image version word
            minor_image_version = contents[marker: marker + 2].hex()
            print(super().reverse_endianness(minor_image_version).hex())
            marker += 2
            # Major subsystem version word
            major_subsystem_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor subsystem version word
            minor_subsystem_version = contents[marker: marker + 2].hex()
            marker += 2
            # Win32 version value dword
            win32_version_value = contents[marker: marker + 4].hex()
            marker += 4
            # Size of image dword
            size_of_image = contents[marker: marker + 4].hex()
            marker += 4
            # Size of headers dword
            size_of_headers = contents[marker: marker + 4].hex()
            marker += 4
            # checksum dword
            checksum = contents[marker: marker + 4].hex()
            marker += 4
            # Subsystem word
            subsystem = contents[marker:marker + 2].hex()
            marker += 2
            # DLL characteristics word
            dll_characteristics = contents[marker:marker + 2].hex()
            marker += 2
            # Size of stack reserve ulonglong/8bytes
            size_of_stack_reserve = contents[marker: marker + 8].hex()
            marker += 8
            # Size of stack commit ulonglong/8bytes
            size_of_stack_commit = contents[marker:marker + 8].hex()
            marker += 8

            size_of_heap_reserve = contents[marker:marker + 8].hex()
            marker += 8

            size_of_heap_commit = contents[marker:marker + 8].hex()
            marker += 8

            loader_flags = contents[marker:marker + 4].hex()
            marker += 4
            
            number_of_rva_and_sizes = contents[marker:marker + 4].hex()
            marker += 4

            optional64_list = [image_base, section_alignment, file_alignment,
                                major_os_sys_version, minor_os_sys_version,
                                major_image_version, minor_image_version, 
                                major_subsystem_version, 
                                minor_subsystem_version, win32_version_value,
                                size_of_image, size_of_headers, checksum,
                                subsystem, dll_characteristics,
                                size_of_stack_reserve, size_of_stack_commit,
                                size_of_heap_reserve, size_of_heap_commit,
                                loader_flags, number_of_rva_and_sizes, marker]
            
            correct_value_list = []
            for _ in range(len(optional64_list) -1 ):
                correct_value = super().reverse_endianness(optional64_list[_]).hex()
                correct_value_list.append(correct_value)
            correct_value_list.append(optional64_list[-1])
            

            return correct_value_list



class Optional32_header(Header):

    def __init__(self, file_to_open, start_bytes):
        self.user_file = file_to_open
        self.start_bytes = start_bytes

    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            base_of_data = contents[int(self.start_bytes):int(self.start_bytes) + 4].hex()
            marker = int(self.start_bytes) + 4
            # First Field in 64 header is ulonglong/8bytes!
            image_base = contents[marker:marker + 4].hex()
            marker += 4
            # Section Alignment DWORD
            section_alignment = contents[marker: marker + 4].hex()
            marker += 4
            # File Alignment DWORD
            file_alignment = contents[marker: marker + 4].hex()
            marker += 4
            # Major Operating system version word
            major_os_sys_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor OS version word
            minor_os_sys_version = contents[marker: marker + 2].hex()
            marker += 2
            # Major image version word
            major_image_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor image version word
            minor_image_version = contents[marker: marker + 2].hex()
            marker += 2
            # Major subsystem version word
            major_subsystem_version = contents[marker: marker + 2].hex()
            marker += 2
            # Minor subsystem version word
            minor_subsystem_version = contents[marker: marker + 2].hex()
            marker += 2
            # Win32 version value dword
            win32_version_value = contents[marker: marker + 4].hex()
            marker += 4
            # Size of image dword
            size_of_image = contents[marker: marker + 4].hex()
            marker += 4
            # Size of headers dword
            size_of_headers = contents[marker: marker + 4].hex()
            marker += 4
            # checksum dword
            checksum = contents[marker: marker + 4].hex()
            marker += 4
            # Subsystem word
            subsystem = contents[marker:marker + 2].hex()
            marker += 2
            # DLL characteristics word
            dll_characteristics = contents[marker:marker + 2].hex()
            marker += 2
            # Size of stack reserve ulonglong/8bytes
            size_of_stack_reserve = contents[marker: marker + 4].hex()
            marker += 8
            # Size of stack commit ulonglong/8bytes
            size_of_stack_commit = contents[marker:marker + 4].hex()
            marker += 8

            size_of_heap_reserve = contents[marker:marker + 4].hex()
            marker += 8

            size_of_heap_commit = contents[marker:marker + 4].hex()
            marker += 8

            loader_flags = contents[marker:marker + 4].hex()
            marker += 4
            
            number_of_rva_and_sizes = contents[marker:marker + 4].hex()
            marker += 4


class Data_directory(Header):

    def __init__(self,file_to_open, start_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes



    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            marker = int(self.begin_bytes)
            print(marker)
            export_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            export_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            import_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            import_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            resource_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            resource_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            exception_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            exception_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            security_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            security_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            base_relocation_table_address = contents[marker:marker + 4].hex()
            marker += 4
            base_relocation_table_size = contents[marker:marker + 4].hex()
            marker += 4
            debug_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            debug_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            architecture_specific_data_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            architecture_specific_data_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            rva_of_global_ptr_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            rva_of_global_ptr_directory_size = contents[marker:marker + 4].hex()
            marker +=4
            tls_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            tls_directory_size = contents[marker:marker + 4].hex()
            marker +=4
            load_configuration_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            load_configuration_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            bound_import_directory_address = contents[marker:marker + 4].hex()
            marker += 4
            bound_import_directory_size = contents[marker:marker + 4].hex()
            marker += 4
            import_address_table_address = contents[marker:marker + 4].hex()
            marker += 4
            import_address_table_size = contents[marker:marker + 4].hex()
            marker += 4
            delay_load_import_address = contents[marker:marker + 4].hex()
            marker += 4
            delay_load_import_size = contents[marker:marker + 4].hex()
            marker += 4
            net_header_address = contents[marker:marker + 4].hex()
            marker += 4
            net_header_size = contents[marker:marker + 4].hex()
            marker += 4
            
            directory_info_list = [export_directory_address, 
                                    export_directory_size, 
                                    import_directory_address,
                                    import_directory_size,
                                    resource_directory_address,
                                    resource_directory_size,
                                    exception_directory_address,
                                    exception_directory_size,
                                    security_directory_address,
                                    security_directory_size,
                                    base_relocation_table_address,
                                    base_relocation_table_size,
                                    debug_directory_address,
                                    debug_directory_size,
                                    architecture_specific_data_directory_address,
                                    architecture_specific_data_directory_size,
                                    rva_of_global_ptr_directory_address,
                                    rva_of_global_ptr_directory_size,
                                    tls_directory_address,
                                    tls_directory_size,
                                    load_configuration_directory_address,
                                    load_configuration_directory_size,
                                    bound_import_directory_address,
                                    bound_import_directory_size,
                                    import_address_table_address,
                                    import_address_table_size,
                                    delay_load_import_address,
                                    delay_load_import_size, net_header_address,
                                    net_header_size, marker]
                
        return directory_info_list

    def correct_endianness(self, directory_info_list):
        for data in range(len(directory_info_list) -1):
            corrected = super().reverse_endianness(directory_info_list[data])
            print(corrected.hex())


class Section_Header(Header):

    def __init__(self,file_to_open, start_bytes):
        self.user_file = file_to_open
        self.begin_bytes = start_bytes


    def parse(self):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            marker = int(self.begin_bytes)
            section_name = contents[marker: marker + 8].hex()
            marker += 8
            self.print_section_names(section_name)
            virtual_size = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(virtual_size).hex())
            virtual_address = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(virtual_address).hex())
            size_of_raw_data = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(size_of_raw_data).hex())
            ptr_to_raw_data = contents[marker:marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(ptr_to_raw_data).hex())
            ptr_to_relocs = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(ptr_to_relocs).hex())
            ptr_to_line_numbers = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(ptr_to_line_numbers).hex())
            num_of_relocs = contents[marker: marker + 2].hex()
            marker += 2
            print(super().reverse_endianness(num_of_relocs).hex())
            num_of_line_nums = contents[marker: marker + 2].hex()
            marker += 2
            print(super().reverse_endianness(num_of_line_nums).hex())
            characteristics = contents[marker: marker + 4].hex()
            marker += 4
            print(super().reverse_endianness(characteristics).hex())
            
            return marker

    

    def print_section_names(self, section_name):
        print(bytearray.fromhex(section_name).decode())








            




test = Dos_header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe",0,64)
res = test.parse()
test.print_information(res)
testStub = Stub_header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", 64, 128)
resStub = testStub.parse()
testStub.print_information(resStub)
test2 = Rich_header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", 128, 224)
res2 = test2.parse()
test2.print_information(res2)
testNtheaders = NT_headers("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", int(res[18]), int(res[18]) + 64)
nt_res = testNtheaders.parse()
number_of_sections = nt_res[2]
print(str(int(number_of_sections, 16)))
print(testNtheaders.print_information(nt_res))
optional_end = int(nt_res[8]) + int(nt_res[6])
optional_test = Optional_header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", int(nt_res[8]), optional_end, nt_res[9])
optional_res = optional_test.parse()
print("Optional Res: " + str(optional_res))
option64test = Optional64_header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", optional_res[8])
opt64return = option64test.parse()
print(opt64return)
start_data_directory_byte = opt64return[21]
dd = Data_directory("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", start_data_directory_byte)
marker_total_before_section = nt_res[6] + nt_res[8]
dd_res =  dd.parse()
print(dd_res)
current_marker = dd_res[-1]
section_start_marker = current_marker + (marker_total_before_section - current_marker)
print(section_start_marker)
section_header = Section_Header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", int(section_start_marker))
section_count = 0
while section_count < int(number_of_sections):
    section_header = Section_Header("C://Users//dcrash0veride//PycharmProjects//dgl5//venv//Scripts//pip3.7.exe", int(section_start_marker))
    section_marker = section_header.parse()
    section_start_marker = section_marker
    section_count += 1
        


#print(dd.correct_endianness(dd.parse()))