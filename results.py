import header_classv2
import directory_class

def dos_results_create(file_to_open):
  dos_header = header_classv2.Header(header_classv2.dos_header_fields, file_to_open, 0, 64)
  return dos_header.parse()

def dos_useful_info(dos_header_results):
  new_header_addy = dos_header_results['e_lfanew']
  marker_location = dos_header_results['current_marker']
  useful_info_tuple = (new_header_addy, marker_location)
  return useful_info_tuple

def stub_results_create(file_to_open):
  stub = header_classv2.Dos_stub(header_classv2.dos_stub_header_fields, file_to_open, 64, 128)
  return stub.is_dos_modified()

def rich_header_results(file_to_open):
  rich_header = header_classv2.Rich_header(header_classv2.rich_header_fields, file_to_open)
  rich_location = rich_header.find_rich_header()
  rich_header_checksum = rich_header.find_comp_ids(rich_location)
  rich_decoded = rich_header.decode_component_ids()
  corrected_rich = rich_header.reverse_endianness(rich_decoded)
  products = rich_header.product_matching(corrected_rich)
  return products

def nt_header_results(file_to_open, start_address):
  nt_header = header_classv2.Header(header_classv2.nt_header_fields, file_to_open, start_address, start_address + 24)
  nt_header_results = nt_header.parse()
  return nt_header_results

def optional64_results(file_to_open, start_address, size):
  optional_header = header_classv2.Header(
                                  header_classv2.optional64_section_header_fields, 
                                  file_to_open, 
                                  start_address, 
                                  start_address + size)
  opt_res = optional_header.parse()
  return opt_res

def section_results(file_to_open, number_of_sections, start_address):
  section_dict = {}
  count = 0
  while count < number_of_sections:
    section_header = header_classv2.Header(header_classv2.section_header_fields, file_to_open, start_address, start_address + 36)
    section_info = section_header.parse()
    count += 1
    start_address = section_info['current_marker']
    name_hex = section_info['Name']
    stripped_name = name_hex.lstrip('0')
    corrected = section_header.reverse_endianness(stripped_name)
    section_name = corrected.decode()
    section_dict[section_name] = section_info
  return section_dict

def export_directory_address_vars(section_results, directory_address):
        for k,v in section_results.items():
            section_end_address = int(v[2], 16) + int(v[3], 16)
            if int(directory_address, 16) > int(section_end_address):
               pass
            elif int(directory_address, 16) < int(section_end_address):
                raw_offset = v[4]
                virtual_addr = v[2]
                max_size = int(v[3], 16) + int(v[4], 16) 
                information_tuple = (raw_offset, directory_address, virtual_addr, max_size)

                return information_tuple
        return "Bad Address"


def get_end_address(sizeOfHeaders, section_results):
   count = 0
   for k,v in section_results.items():
      values = section_results[k]
      size = values[2]
      count += int(size, 16)
   count += int(sizeOfHeaders, 16)
   return count


def import_directory_results(file_to_open, raw_offset, directory_address, virtual_address, directory_size, max_size):
  import_directory = directory_class.Directory(file_to_open, raw_offset, directory_address, virtual_address, max_size)
  imports = import_directory.import_directory(file_to_open, directory_size)
  decoded_imports = import_directory.parse_imports(imports)
  ressy_dict = {}
  for k,v in decoded_imports.items():
     cleaned_list = []
     for j in range(0, len(v)):
        entry = v[j]
        cleaned_list.append(entry[:-1])
     ressy_dict[k] = cleaned_list
  return ressy_dict
    