import re
import json
import subprocess
import argparse

from enum import Enum

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

DEBUG = True

DNS_PROGRAM_NAME = './dns'
DIG_PROGRAM_NAME = 'dig'

DEFAULT_SERVER   = 'dns.google'
DEFAULT_ADDRESS  = 'www.google.com'
DEFAULT_IPv4     = '140.82.121.4' # github.com

COMPARE_TTL = False # TTL will most likely be different so no point to compare

class DnsSection(Enum):
    QUESTION   = "Question section"
    ANSWER     = "Answer section"
    AUTHORITY  = "Authority section"
    ADDITIONAL = "Additional section"

class DigSection(Enum):
    QUESTION = "QUESTION SECTION"
    ANSWER = "ANSWER SECTION"
    AUTHORITY = "AUTHORITY SECTION"
    ADDITIONAL = "ADDITIONAL SECTION"

    
def dns_get_sections(lines) -> dict:
    sections = {}

    patterns = [re.escape(section.value) for section in DnsSection]
    pattern = '|'.join(patterns)

    idx = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    assert len(idx) == len(DnsSection), \
        f"{DNS_PROGRAM_NAME} Error: Output must contain all {len(DnsSection)} sections"
    
    for i, id in enumerate(idx):
        ds = list(DnsSection)[i]
        sl  = lines[id]
        match = re.search(r"\((.*?)\)", sl)
        if match:
            try:
                cnt = int(match.group(1))
            except ValueError:
                print(f"{DNS_PROGRAM_NAME} Error: Could not convert [{match.group(1)}] to an integer")
                exit(1)
        else:
            print(f"{DNS_PROGRAM_NAME} Error: Could not find number of lines in section")
            exit(1)
        
        dns_sec = []
        for line in lines[id+1:id+1+cnt]:
            parts = [part.strip() for part in line.strip(";\n").split(',')]
            try:
                dns = {
                    'name' : parts[0],
                    'type' : parts[1],
                    'class': parts[2]
                }
                if ds is not DnsSection.QUESTION:
                    dns['ttl']   = parts[3]
                    dns['rdata'] = parts[4]
            except IndexError:
                print(f"{DNS_PROGRAM_NAME} Error: Not enough parts in line")
                exit(1)
            dns_sec.append(dns)
        sections[ds] = dns_sec
    
    return sections

def dig_get_sections(lines) -> dict:
    sections = {}

    patterns = [re.escape(section.value) for section in DigSection]
    pattern = '|'.join(patterns)

    idx = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    idx.append(len(lines)-1)
    
    for i in range(len(idx)-1):
        id = idx[i]
        next_id = idx[i+1]
        ds = list(DigSection)[i]

        dig_sec = []
        for line in lines[id+1:next_id]:
            if line.strip() == '':
                continue
            parts = [part.strip() for part in line.strip(";\n").split()]
            try:
                dig = {
                    'name': parts[0],
                }
                
                if ds is not DigSection.QUESTION:
                    if len(parts) > 4:
                        dig['type']  = parts[3]
                        dig['class'] = parts[2]
                        dig['ttl']   = parts[1]
                        dig['rdata'] = parts[4]
                    else:
                        dig['type']  = parts[2]
                        dig['class'] = parts[1]
                        dig['rdata'] = parts[3]
                else:
                    dig['type']  = parts[2]
                    dig['class'] = parts[1]

            except IndexError:
                print(f"{DIG_PROGRAM_NAME} Error: Not enough parts in line")
                exit(1)
            dig_sec.append(dig)
        sections[ds] = dig_sec
    
    # Append empty missing sections
    for ds in DigSection:
        if ds not in sections:
            sections[ds] = []
    
    return sections

def compare_section_line(dig_line, dns_line):
    if dig_line['name']   != dns_line['name'] or \
        dig_line['class'] != dns_line['class'] or \
        dig_line['type']  != dns_line['type']:
        return False
        
    if COMPARE_TTL:
        if dig_line.get('ttl') != dns_line.get('ttl'):
            return False
        
    if dig_line.get('rdata') != dns_line.get('rdata'):
        return False
    
    return True

def compare_section(dig_section, dns_section):

    if dig_section and dns_section:

        for dns_line in dns_section:
            line_found = False
            if DEBUG:
                print(f"\t{bcolors.OKCYAN}{DNS_PROGRAM_NAME} looking for line: {dns_line}{bcolors.ENDC}")
            for dig_line in dig_section:
                if compare_section_line(dig_line, dns_line):
                    line_found = True
                    break
            if line_found:
                if DEBUG:
                    print(f"\t\t{bcolors.OKGREEN}LINE OK{bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}Error: {DNS_PROGRAM_NAME} is missing a line in [{dns_section}]{bcolors.ENDC}")
                return False
        
    elif dns_section and not dig_section:
        print(f"{bcolors.FAIL}Error: {DNS_PROGRAM_NAME} section [{dns_section}] must be empty{bcolors.ENDC}")
    elif not dns_section and dig_section:
        print(f"{bcolors.FAIL}Error: {DNS_PROGRAM_NAME} section [{dns_section}] must NOT be empty{bcolors.ENDC}")
        
    if DEBUG:
        print(f"\t{bcolors.OKGREEN}SECTION OK{bcolors.ENDC}")
    return True

def compare_output(dig_output, dns_output):
    dig_sections = dig_get_sections(dig_output)
    dns_sections = dns_get_sections(dns_output)

    for (dig, dns) in zip(DigSection, DnsSection):
        if DEBUG:
            print(f"{bcolors.OKBLUE}Comparing {dig} to {dns}{bcolors.ENDC}")
        if not compare_section(dig_sections[dig], dns_sections[dns]):
            return False
    
    return True

def run_test(case):
    try:
        server  = case['server'] if 'server' in case else DEFAULT_SERVER
        if 'address' in case:
            address = case['address']
        else:
            address = DEFAULT_ADDRESS if not case['inverse'] else DEFAULT_IPv4

        dig_command = ['dig']
        #dig_command.append('+short')
        #dig_command.append('+answer')
        dig_command.append('+nostats')
        #dig_command.append('+nocomments')
        dig_command.append('+recurse' if case['recursive'] else '+norecurse')
        dig_command.append('@' + server)
        if case['inverse']:
            dig_command.append('-x')
        elif case['aaaa']:
            dig_command.append('AAAA')
        dig_command.append(address)
        

        # Define the command to run the dns program executable
        dns_command = [DNS_PROGRAM_NAME]
        if case['recursive']:
            dns_command.append('-r')
        if case['aaaa']:
            dns_command.append('-6')
        if case['inverse']:
            dns_command.append('-x')
        
        dns_command.append('-s')
        dns_command.append(server)

        dns_command.append(address)
        
        if 'port' in case:
            dns_command.append('-p')
            dns_command.append(str(case['port']))
    except KeyError:
        print(f"{bcolors.FAIL}Error: Json is missing a required field.{bcolors.ENDC}")
        exit(1)

    # Run the command and capture the output
    dig_result = subprocess.run(dig_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if dig_result.returncode == 0:
        dig_output = dig_result.stdout
    else:
        dig_output = dig_result.stderr
        print(f"{bcolors.FAIL}Error: Invalid input. The dig program failed with an error.{bcolors.ENDC}")
        print(f"{bcolors.FAIL}stderr: {dig_output}{bcolors.ENDC}")
        exit(1)

    # Run the command and capture the output and exit code
    dns_result = subprocess.run(dns_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    # Check the exit code
    if dns_result.returncode == 0:
        dns_output = dns_result.stdout
    else:
        if 'should_fail' in case and case['should_fail']:
            return True
        else:
            dns_output = dns_result.stderr
            print(f"{bcolors.FAIL}Error: The {DNS_PROGRAM_NAME} program failed with an error.{bcolors.ENDC}")
            print(f"{bcolors.FAIL}stderr: {dns_output}{bcolors.ENDC}")
            exit(1)

    if DEBUG:
        print(dig_output)
        print("\n\n")
        print(dns_output)


    return compare_output(dig_output.splitlines(), dns_output.splitlines())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="enable debug mode", action="store_true")
    args = parser.parse_args()
    
    if args.debug:
        print("Debug mode enabled.")
        DEBUG = True
    else:
        print("Debug mode disabled. To enable debug mode use '-d'")
        DEBUG = True

    with open('test_cases.json', 'r') as f:
        test_cases = json.load(f)
        passed = 0
        for i, case in enumerate(test_cases):
            if run_test(case):
                passed += 1
                print(f"{bcolors.OKGREEN}TEST PASSED ({i+1}/{len(test_cases)}).{bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}TEST FAILED ({i+1}/{len(test_cases)}).{bcolors.ENDC}")
        print(f"--------------------------------------------------------------------")
        print(f"{bcolors.OKGREEN}PASSED: {passed}/{len(test_cases)}.{bcolors.ENDC}")
        if passed != len(test_cases):
            print(f"{bcolors.FAIL}FAILED: {len(test_cases)-passed}/{len(test_cases)}.{bcolors.ENDC}")
        
    