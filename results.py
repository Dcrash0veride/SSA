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

def import_directory_results(file_to_open, baseOfCode, directory_address, directory_size):
  import_directory = directory_class.Directory(file_to_open, baseOfCode, directory_address)
  imports = import_directory.import_directory(file_to_open, int(directory_size, 16))
  decoded_imports = import_directory.parse_imports(imports)
  ressy_dict = {}
  for k,v in decoded_imports.items():
    method_list = []
    for j in range(len(v)):
      method_list.append(import_directory.resolve_method_name(v[j]))
    ressy_dict[k] = method_list
  return ressy_dict