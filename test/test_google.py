"""
@author Vadim Goncearenco (xgonce00)
""" 

import json
import requests
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

DEFAULT_SERVER   = 'dns.google'
DEFAULT_ADDRESS  = 'www.google.com'
DEFAULT_IPv4     = '140.82.121.4' # github.com

def get_dns_google_answers(server, address, port, recursive, inverse, aaaa):
    url = f"https://{server}/resolve?name={address}&type={'AAAA' if aaaa else 'A'}&{'rd' if recursive else 'no'}rec&{'cd' if inverse else 'no'}cd"
    response = requests.get(url, timeout=10)
    response_json = response.json()
    answers = response_json.get("Answer", [])
    # for answer in answers:
    #     if answer["type"] == (28 if aaaa else 1):
    #         ip_address = answer["data"]
    #         print(f"{address} resolves to {ip_address}")
    #         break
    if len(answers) == 0:
        print(f"Could not resolve {address}")
    
    return answers

def compare_output(expected, actual):
    if expected == actual:
        print(f"{bcolors.OKGREEN}Test passed!{bcolors.ENDC}")
        return True
    else:
        print(f"{bcolors.FAIL}Test failed!{bcolors.ENDC}")
        print(f"{bcolors.FAIL}Expected: {expected}{bcolors.ENDC}")
        print(f"{bcolors.FAIL}Actual: {actual}{bcolors.ENDC}")
        return False

def run_test(case):
    server = case.get("server", DEFAULT_SERVER)
    address = case.get("address", DEFAULT_ADDRESS)
    port = case.get("port", 53)
    recursive = case.get("recursive", True)
    inverse = case.get("inverse", False)
    aaaa = case.get("aaaa", False)

    google_answers = get_dns_google_answers(server, address, port, recursive, inverse, aaaa)
    
    dns_command = [DNS_PROGRAM_NAME]
    if recursive:
        dns_command.append('-r')
    if aaaa:
        dns_command.append('-6')
    if inverse:
        dns_command.append('-x')
    
    dns_command.append('-s')
    dns_command.append(server)

    dns_command.append(address)
    
    if 'port' in case:
        dns_command.append('-p')
        dns_command.append(str(case['port']))

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
        print(dns_output)

    return compare_output(google_answers, dns_output)



if __name__ == "__main__":
    with open("test_cases.json", "r") as f:
        test_cases = json.load(f)

    for test_case in test_cases:
        try:
            run_test(test_case)
        except Exception as e:
            print(f"Error resolving {test_case['address']}: {e}")