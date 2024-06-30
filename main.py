import results
import colorize
import click


"""Main.py will hold the driver code and user interactions"""

"""TODO:  
start testing, 
fix dll method name cutoff, 
add support for optional32, 
get hashes, get strings 
"""


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

@click.command()
@click.option('--file', help='The file to parse')

def parse_executable(file):
  colorize.pretty_print_banner(banner_text)
  file_to_open = file
  dos_ressy = results.dos_results_create(file_to_open)
  dos_new_header = results.dos_useful_info(dos_ressy)
  colorize.pretty_print_results(['DOS_HEADER_FIELDS', 'DOS_HEADER_VALUES'], dos_ressy)
  rh = results.rich_header_results(file_to_open)
  colorize.pretty_print_results(['Version', 'Product', 'Build ID', '# of times used'], rh)
  nt_ressy = results.nt_header_results(file_to_open, int(dos_ressy['e_lfanew'], 16))
  colorize.pretty_print_results(['NT_HEADER_FIELDS', 'NT_HEADER_VALUES'], nt_ressy)
  opt_size = int(nt_ressy['SizeOfOptionalHeader'], 16)
  opt_start = nt_ressy['current_marker']
  opt_ressy = results.optional64_results(file_to_open, opt_start, opt_size)
  colorize.pretty_print_results(['OPTIONAL_FIELD', 'OPTIONAL_VALUE'], opt_ressy)
  number_of_sections = int(nt_ressy['NumberOfSections'])
  section_start = int(nt_ressy['SizeOfOptionalHeader'], 16) + int(nt_ressy['current_marker'])
  section_ressy = results.section_results(file_to_open, number_of_sections, section_start)
  section_dict = {}
  for k,v in section_ressy.items():
    loose_list = []
    for j in v:
      loose_list.append(v[j])
    section_dict[k] = loose_list
  colorize.pretty_print_results(['Name', 'SECTION_FIELD_VALUES'], section_dict)
  directory_info = results.export_directory_address_vars(section_dict, opt_ressy['ImportDirectoryAddress'])
  print(opt_ressy['ImportDirectoryAddress'])
  # Time to deal with directories Having issue with parsing directories. Offset should be 1400 I think
  raw_offset = int(directory_info[0], 16)
  dir_addr = int(directory_info[1], 16)
  virt_addr = int(directory_info[2], 16)
  mx_size = int(directory_info[3])
  imp_ressy = results.import_directory_results(file_to_open, raw_offset, dir_addr, virt_addr, opt_ressy['ImportDirectorySize'], mx_size)
  for k,v in imp_ressy.items():
    print(colorize.terminal_colorize() + "{}\033[0m".format(k, end=" "))
    print(colorize.terminal_colorize() + "{}\033[0m".format(v, end='\n'))
    print('\n')

  
if __name__=='__main__':
  parse_executable()


