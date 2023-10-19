import re
import json
import subprocess

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
    QUESTION = "Question section"
    ANSWER = "Answer section"
    AUTHORITY = "Authority section"
    ADDITIONAL = "Additional section"

class DigSection(Enum):
    QUESTION = "QUESTION SECTION"
    ANSWER = "ANSWER SECTION"
    AUTHORITY = "AUTHORITY SECTION"
    ADDITIONAL = "ADDITIONAL SECTION"



def dns_get_section(lines, section : DnsSection) -> dict:
    for i, line in enumerate(lines):
        if section.value in line:
            first = line.find("(")
            last = line.find(")")
            num = line[first+1:last]
            try:
                if int(num) == 0:
                    return None
            except ValueError:
                print(f"{DNS_PROGRAM_NAME} Error: Could not convert [{num}] to an integer")
                exit(1)

            try:
                next_line = lines[i+1]
            except IndexError:
                print(f"{DNS_PROGRAM_NAME} Error: Section has [{num}] queries but there are no more lines in the output")
                exit(1)

            parts = [part.strip() for part in next_line.strip(";\n").split(',')]
            try:
                dns = {
                    'name': parts[0],
                    'type': parts[1],
                    'class': parts[2]
                }
                if section is not DnsSection.QUESTION:
                    dns['ttl'] = parts[3]
                    dns['rdata'] = parts[4]
            except IndexError:
                print(f"{DNS_PROGRAM_NAME} Error: Not enough parts in line")
                exit(1)
            return dns
    print(f"{DNS_PROGRAM_NAME} Error: Could not find [{section}] section in output")
    exit(1)


def dig_get_section(lines, section : DigSection) -> dict:
    for i, line in enumerate(lines):
        if section.value in line:
            try:
                next_line = lines[i+1]
            except IndexError:
                print(f"{DIG_PROGRAM_NAME} Error: Section contaisn no more lines")
                exit(1)
            # write code to split next_line by whitespace
            parts = [part.strip() for part in next_line.strip(";\n").split()]
            try:
                dig = {
                    'name': parts[0],
                    
                    #'class': parts[1],
                    # 'ttl': parts[3],
                    # 'rdata' : parts[4]
                }
                if section is not DigSection.QUESTION:
                    if len(parts) > 4:
                        dig['type'] = parts[3]
                        dig['class'] = parts[2]
                        dig['ttl'] = parts[1]
                        dig['rdata'] = parts[4]
                    else:
                        dig['type'] = parts[2]
                        dig['class'] = parts[1]
                        dig['rdata'] = parts[3]
                else:
                    dig['type'] = parts[2]
                    dig['class'] = parts[1]

            except IndexError:
                print(f"{DIG_PROGRAM_NAME} Error: Not enough parts in line")
                exit(1)
            return dig
    return None        


def compare_section(dig_output, dns_output, dig_section, dns_section):
    if DEBUG:
        print(f"Comparing {dig_section} to {dns_section}")

    dns_sec = dns_get_section(dns_output, dns_section)
    dig_sec = dig_get_section(dig_output, dig_section)

    if dns_sec is not None and dig_sec is not None:        
        if DEBUG:
            print(f"\tdig: {dig_sec}\n")
            print(f"\tdns: {dns_sec}")

        if dig_sec['name'] != dns_sec['name'] or \
                dig_sec['class'] != dns_sec['class'] or \
                dig_sec['type'] != dns_sec['type']:
            return False
        
        if COMPARE_TTL:
            if dig_sec.get('ttl') != dns_sec.get('ttl'):
                return False
            
        if dig_sec.get('rdata') != dns_sec.get('rdata'):
            return False
    elif dns_sec is not None and dig_sec is None:
        print(f"{bcolors.FAIL}Error: {DNS_PROGRAM_NAME} has [{dns_section}] section that shouldn't be there{bcolors.ENDC}")
    elif dns_sec is None and dig_sec is not None:
        print(f"{bcolors.FAIL}Error: {DNS_PROGRAM_NAME} is missing [{dns_section}] section{bcolors.ENDC}")
        
    if DEBUG:
        print(f"\t{bcolors.OKGREEN}COMPARISON SUCCESS{bcolors.ENDC}")
    return True

def compare_output(dig_output, dns_output):
   
    for dig_section, dns_section in zip(DigSection, DnsSection):
        if not compare_section(dig_output, dns_output, dig_section, dns_section):
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
        # if case['aaaa']:
        #     dig_command.append('-6')
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
    with open('test_cases.json', 'r') as f:
        test_cases = json.load(f)
        passed = 0
        for i, case in enumerate(test_cases):
            if run_test(case):
                passed += 1
                print(f"{bcolors.OKGREEN}PASS ({i+1}/{len(test_cases)}).{bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}FAIL ({i+1}/{len(test_cases)}).{bcolors.ENDC}")
        print(f"--------------------------------------------------------------------")
        print(f"{bcolors.OKGREEN}PASSED: {passed}/{len(test_cases)}.{bcolors.ENDC}")
        if passed != len(test_cases):
            print(f"{bcolors.FAIL}FAILED: {len(test_cases)-passed}/{len(test_cases)}.{bcolors.ENDC}")
        
    