import random
from tabulate import tabulate

def terminal_colorize():
  color_choices = ('\033[0;31m', '\033[0;32m', '\033[0;34m', '\033[0;35m',
                   '\033[0;36m', '\033[1;31m', '\033[1;32m', '\033[1;33m',
                   '\033[1;34m', '\033[1;35m', '\033[1;36m', '\033[1;37m',)
  color_choice = random.choice(color_choices)
  return color_choice

def pretty_print_results(header_fields, results):
  if isinstance(results, dict):
    print(terminal_colorize() + "{}\033[0m".format(tabulate(results.items(), headers=header_fields)))
    print('\n')
  elif isinstance(results, list):
    print(terminal_colorize() + "{}\033[0m".format(tabulate(results, headers=header_fields)))
    print('\n')

def pretty_print_banner(banner_text):
  print(terminal_colorize() + "{}\033[0m".format(banner_text))
  print('\n')