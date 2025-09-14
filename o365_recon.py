#!/usr/bin/env python3
"""
O365 Recon - Microsoft 365 Domain and User Account Enumeration Tool

By notalex.sh
"""

import argparse
import logging
import re
import sys
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnsiColors:
    """ANSI color codes for stylish terminal output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    SUCCESS = '✓'
    FAILURE = '✗'
    INFO = '›'

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        'INFO': AnsiColors.GREEN, 'WARNING': AnsiColors.YELLOW,
        'ERROR': AnsiColors.RED, 'DEBUG': AnsiColors.CYAN, 'RESET': AnsiColors.RESET
    }

    def format(self, record):
        log_color = self.LEVEL_COLORS.get(record.levelname, self.LEVEL_COLORS['RESET'])
        symbol = {
            'INFO': f"{AnsiColors.GREEN}{AnsiColors.SUCCESS}{AnsiColors.RESET}",
            'ERROR': f"{AnsiColors.RED}{AnsiColors.FAILURE}{AnsiColors.RESET}"
        }.get(record.levelname, AnsiColors.INFO)
        return f" {symbol} {record.getMessage()}"

def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    return logger

logger = setup_logger(__name__)

class HTTPClient:
    # HTTP client with retry logic
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.session = self._create_session(max_retries)
    
    def _create_session(self, max_retries: int) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def get(self, url: str, params: Optional[Dict] = None) -> requests.Response:
        try:
            return self.session.get(url, params=params, timeout=self.timeout, verify=False)
        except Exception as e:
            logger.error(f"GET request failed for {url}: {e}")
            raise
    
    def post(self, url: str, json_data: Optional[Dict] = None) -> requests.Response:
        try:
            return self.session.post(url, json=json_data, timeout=self.timeout, verify=False)
        except Exception as e:
            logger.error(f"POST request failed for {url}: {e}")
            raise

class DomainValidator:
    # Validates if a domain exists in Microsoft 365
    def __init__(self):
        self.http_client = HTTPClient()
        self.getuserrealm_url = "https://login.microsoftonline.com/getuserrealm.srf"
    
    def check_domain(self, domain: str) -> Dict:
        result = {'domain': domain, 'exists': False, 'namespace_type': None, 'error': None}
        try:
            domain = domain.strip().lower()
            if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
                result['error'] = 'Invalid domain format'
                return result
            
            params = {'login': f'user@{domain}', 'json': '1'}
            response = self.http_client.get(self.getuserrealm_url, params=params)
            
            if response.status_code != 200:
                result['error'] = f'HTTP {response.status_code}'
                return result
            
            data = response.json()
            namespace_type = data.get('NameSpaceType', '').strip()
            result['namespace_type'] = namespace_type
            
            if namespace_type in ['Managed', 'Federated']:
                result['exists'] = True
                result['tenant_id'] = data.get('TenantId')
                if namespace_type == 'Federated':
                    result['federation_brand'] = data.get('FederationBrandName')
            elif namespace_type != 'Unknown':
                result['error'] = f'Unexpected NameSpaceType: {namespace_type}'
                
        except Exception as e:
            result['error'] = f'Error checking domain: {str(e)}'
        return result

class UserValidator:
    # Validates if a user account exists in Microsoft 365
    def __init__(self):
        self.http_client = HTTPClient()
        self.credential_type_url = "https://login.microsoftonline.com/common/GetCredentialType"
    
    def check_user(self, email: str) -> Dict:
        result = {'valid': False, 'details': {}, 'error': None}
        try:
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                result['error'] = 'Invalid email format'
                return result
            
            response = self.http_client.post(self.credential_type_url, json_data={"Username": email.strip().lower()})
            
            if response.status_code != 200:
                result['error'] = f'HTTP {response.status_code}'
                return result
            
            data = response.json()
            if_exists_result = data.get('IfExistsResult')
            result['details']['if_exists_result'] = if_exists_result
            
            # A result of 0, 5, or 6 indicates a valid user identity
            if if_exists_result in [0, 5, 6]:
                result['valid'] = True
            elif if_exists_result != 1:
                result['error'] = f'Unexpected IfExistsResult: {if_exists_result}'
            
            if data.get('DesktopSsoEnabled'):
                result['details']['desktop_sso'] = True
                
        except Exception as e:
            result['error'] = f'Error checking user: {str(e)}'
        return result

class O365Recon:
    # Main application class for M365 validation
    def __init__(self, verbose: bool = False):
        self.domain_validator = DomainValidator()
        self.user_validator = UserValidator()
        self.verbose = verbose
    
    def validate_domain(self, domain: str) -> dict:
        logger.info(f"Checking domain: {AnsiColors.BOLD}{domain}{AnsiColors.RESET}")
        return self.domain_validator.check_domain(domain)

    def validate_user(self, email: str) -> dict:
        logger.info(f"Checking user: {AnsiColors.BOLD}{email}{AnsiColors.RESET}")
        return self.user_validator.check_user(email)

def print_banner():
    c = AnsiColors
    print(f"""
    {c.BLUE}╔═══════════════════════════════════════════════════════════════╗
    ║   {c.BOLD}O365 Recon{c.RESET}{c.BLUE}     🕵️‍♂️   M365 Enumeration Tool                   ║
    ╚═══════════════════════════════════════════════════════════════╝{c.RESET}
    """)

def print_domain_result(result: dict):
    c = AnsiColors
    status_color = c.GREEN if result.get('exists') else c.RED
    status_symbol = c.SUCCESS if result.get('exists') else c.FAILURE
    status_text = "VALID" if result.get('exists') else "NOT FOUND"
    
    print(f"\n {c.BOLD}DOMAIN VALIDATION RESULT{c.RESET}")
    print(f" {c.GREY}──────────────────────────{c.RESET}")
    print(f" {c.INFO} Domain:    {c.BOLD}{result.get('domain', 'N/A')}{c.RESET}")
    print(f" {status_symbol} Status:    {status_color}{c.BOLD}{status_text}{c.RESET}")

    if result.get('exists'):
        print(f" {c.INFO} Type:      {c.CYAN}{result.get('namespace_type', 'N/A')}{c.RESET}")
        if result.get('federation_brand'):
            print(f" {c.INFO} Brand:     {result.get('federation_brand')}")
        if result.get('tenant_id'):
            print(f" {c.INFO} Tenant ID: {c.GREY}{result.get('tenant_id')}{c.RESET}")
    if result.get('error'):
        print(f" {c.FAILURE} Error:     {c.RED}{result.get('error')}{c.RESET}")
    print()

def print_user_result(result: dict, email: str):
    c = AnsiColors
    status_color = c.GREEN if result.get('valid') else c.RED
    status_symbol = c.SUCCESS if result.get('valid') else c.FAILURE
    status_text = "VALID" if result.get('valid') else "INVALID / NOT FOUND"
    
    print(f"\n {c.BOLD}USER VALIDATION RESULT{c.RESET}")
    print(f" {c.GREY}────────────────────────{c.RESET}")
    print(f" {c.INFO} Email:    {c.BOLD}{email}{c.RESET}")
    print(f" {status_symbol} Status:   {status_color}{c.BOLD}{status_text}{c.RESET}")

    if result.get('valid') and result.get('details', {}).get('desktop_sso'):
        print(f" {c.INFO} SSO:      {c.YELLOW}Desktop SSO Enabled{c.RESET}")
    if result.get('error'):
        print(f" {c.FAILURE} Error:    {c.RED}{result.get('error')}{c.RESET}")
    
    print(f"\n {c.GREY}Note: This tool checks for a valid Microsoft login identity (User Principal Name).")
    print(f" An 'INVALID' result means the address tested is not a login ID, even if it's a")
    print(f" valid email alias. For example, your login might be 'e12345' not 'firstname.lastname'.{c.RESET}\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description='O365 Recon - M365 Domain and User Account Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check if a domain exists in M365
  %(prog)s -d contoso.com

  # Validate a single user account
  %(prog)s -u john.doe@contoso.com
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Check a single domain')
    group.add_argument('-u', '--user', help='Validate a single user account')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging')

    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    recon = O365Recon(verbose=args.verbose)
    
    if args.domain:
        result = recon.validate_domain(args.domain)
        print_domain_result(result)
    
    if args.user:
        result = recon.validate_user(args.user)
        print_user_result(result, args.user)

if __name__ == '__main__':
    main()