

class Directory():

    def __init__(self, user_file, base, directory_address, vaddr, max_size):
        self.user_file = user_file
        self.base = base
        self.directory_address = directory_address
        self.virtual_address = vaddr
        self.max_size = max_size
      


    def calculate_address(self):
        print("calculating address with the following values: ", self.base, self.directory_address, self.virtual_address)
        addr = int(self.base) + int(self.directory_address) - int(self.virtual_address)
        print("Result of calculation: ", addr)
        return addr

    def correct_endianness(self,first_thunk):
        if type(first_thunk) == str:
            byte_data = bytearray.fromhex(first_thunk)
            byte_data.reverse()
            return byte_data.hex()
        else:
            convert_to_string = str(first_thunk)
            byte_data = bytearray.fromhex(convert_to_string)
            byte_data.reverse()
            return byte_data.hex()


    def import_directory(self, user_file, size):
        with open(user_file, 'rb') as f:
            contents = f.read()
            offset = self.calculate_address()
            start = int(offset)
            stop = int(offset) + int(size, 16)
            chunk_size = int('14', 16)
            marker = 0
            directory_information = contents[offset:stop]
            directory_information_list = []
            while marker < len(directory_information):
                dir_info_chunk = directory_information[marker:marker + chunk_size]
                rva_lookup = dir_info_chunk[:4].hex()
                time_date_stamp_ = dir_info_chunk[4:8].hex()
                forwarder_chain = dir_info_chunk[8:12].hex()
                name_rva = dir_info_chunk[12:16].hex()
                import_address_table_rva = dir_info_chunk[16:20].hex()
                dir_info_tuple = (self.correct_endianness(rva_lookup), 
                                  self.correct_endianness(time_date_stamp_), 
                                  self.correct_endianness(forwarder_chain), 
                                  self.correct_endianness(name_rva), 
                                  self.correct_endianness(import_address_table_rva))
                directory_information_list.append(dir_info_tuple)
                marker += chunk_size
        return directory_information_list


    def import_methods(self, thunk_start, thunk_end):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            t_start = int(thunk_start, 16) - int('1000', 16)
            t_end = int(thunk_end, 16) - int('1000', 16)
            mthd_info = contents[t_start:t_end]
            marker = 0
            chunk_size = 8
            method_list = []
            while marker < len(mthd_info):
                method_info_chunk = mthd_info[marker:marker + chunk_size].hex()
                mthd_chunk = self.correct_endianness(method_info_chunk)
                if mthd_chunk.lstrip('0') != '':
                    method_list.append(mthd_chunk.lstrip('0'))
                marker += chunk_size
            return method_list

    # This method returns a dictionary of DLL imports, and the thunks associated with the dll
    def parse_imports(self, import_directories):
        results = {}
        dll_names = []
        for entry in import_directories:
            original_first_thunk = entry[0]
            time_data_stamp = entry[1]
            forwarder = entry[2]
            name_rva = entry[3]
            first_thunk = entry[4]
            if name_rva != '00000000':
                library_name_location = int(self.base) + int(name_rva, 16) - int(self.virtual_address)
                first_thunk_address = int(self.base) + int(first_thunk, 16) - int(self.virtual_address)
                top_tuple = (self.resolve_name(library_name_location), first_thunk_address)
                # Creates a list of tuples contained the library_name and the first_thunk addy, run in reverse to occupy space betwizyt
                dll_names.append(top_tuple)
        for entry in dll_names:
            with open(self.user_file, 'rb') as f:
                method_thunks = []
                contents = f.read()
                thunk_start = entry[1]
                chunk = 8
                info = contents[thunk_start:thunk_start + chunk].hex()
                while info.lstrip('0') != '':
                    info = self.correct_endianness(info)
                    method_thunks.append(info.lstrip('0'))
                    thunk_start += chunk
                    info = contents[thunk_start: thunk_start + chunk].hex()
                results[entry[0]] = method_thunks
        imports_dictionary = {}
        for k,v in results.items():
            imports_list = []
            for _ in range(0, len(v)):
                real_address = int(self.base) + int(v[_], 16) - int(self.virtual_address)
                
                imports_list.append(self.resolve_method_name(real_address))
            imports_dictionary[k] = imports_list
        return imports_dictionary

            
    def resolve_name(self, name_location):
        with open(self.user_file, 'rb') as f:
            contents = f.read()
            chunk_size = 8
            name = []
            base = name_location
            name_chunk = contents[name_location:name_location + chunk_size].hex()
            while '00' not in name_chunk:
                chunk_size += 1
                name_chunk = contents[base:base + chunk_size].hex()
            name = name_chunk[:-2]
            return str(bytes.fromhex(name).decode('utf-8'))

    
    def resolve_method_name(self, name_location):
        with open(self.user_file, 'rb') as f:
            if int(name_location) > int(self.max_size):
                return hex(name_location)
            contents = f.read()
            chunk_size = 1
            name = []
            base = int(name_location) + 2
            name_chunk = contents[base:base + int(chunk_size)].hex()
            while '00' not in name_chunk:
                chunk_size += 1
                name_chunk = contents[int(base):int(base) + int(chunk_size)].hex()
            name = name_chunk
        return str(bytes.fromhex(name).decode('utf-8'))
