import argparse
import requests
import os
import re
import json
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque
from colorama import Fore, Style, init

init()

BANNERS = {
    'default': f"""{Fore.RED}            
⠤⣤⣤⣤⣄⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⠤⠤⠴⠶⠶⠶⠶
⢠⣤⣤⡄⣤⣤⣤⠄⣀⠉⣉⣙⠒⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⠘⣉⢡⣤⡤⠐⣶⡆⢶⠀⣶⣶⡦
⣄⢻⣿⣧⠻⠇⠋⠀⠋⠀⢘⣿⢳⣦⣌⠳⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠞⣡⣴⣧⠻⣄⢸⣿⣿⡟⢁⡻⣸⣿⡿⠁
⠈⠃⠙⢿⣧⣙⠶⣿⣿⡷⢘⣡⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣷⣝⡳⠶⠶⠾⣛⣵⡿⠋⠀⠀
⠀⠀⠀⠀⠉⠻⣿⣶⠂⠘⠛⠛⠛⢛⡛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠛⠀⠉⠒⠛⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢻⡁⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    Arachnid - by palq & mzz_exe
    """,
    'matrix': f"""{Fore.GREEN}
        Arachnid 
⣤⣤⣤⡄⠀       ⠀⠀⠀⠀⠀⠀⠀⢠⣤⣤⣤
⣿⣿⡿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
⣿⣿⡇⠀⢠⣤⣤⣠⣴⣶⣦⣄⣠⣴⣶⣦⣄⠀⠀⢸⣿⣿
⣿⣿⡇⠀⢸⣿⣿⠋⠁⠙⣿⣿⠏⠁⠉⣿⣿⡆⠀⢸⣿⣿
⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⢸⣿⣿
⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⢸⣿⣿
⣿⣿⡇⠀⠈⠛⠛⠀⠀⠀⠛⠛⠀⠀⠀⠛⠛⠁⠀⢸⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
⣿⣿⣷⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣾⣿⣿
⠛⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠛
     {Fore.WHITE}Palq - mzz_exe{Fore.RESET}
    """,
    'skull': f"""{Fore.WHITE}
    Arachnid 
           ______
        .-"      "-.
       /            \\
      |              |
      |,  .-.  .-.  ,|
      | )(__/  \\__)( |
      |/     /\\     \\|
      (_     ^^     _)
       \\__|IIIIII|__/
        | \\IIIIII/ |
        \\          /
  {Fore.WHITE}palq   `--------`  mzz_exe{Fore.RESET}
    """
}

class WebScanner:
    def __init__(self, user_prompt=f"{Fore.WHITE}ArachnidCMD>{Fore.RESET}"):
        self.user_prompt = user_prompt
        self.current_banner = 'default'
        
    def set_banner(self, banner_name):
        if banner_name in BANNERS:
            self.current_banner = banner_name
            print(f"{Fore.GREEN}[+] Banner set to {banner_name}{Fore.RESET}")
        else:
            print(f"{Fore.RED}[-] Banner {banner_name} not found. Available banners: {', '.join(BANNERS.keys())}{Fore.RESET}")
    
    def show_banner(self):
        print(BANNERS[self.current_banner])
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.show_banner()
    
    def scan_xss(self, url):
        print(f"{Fore.GREEN}[*] Scanning for XSS vulnerabilities on {url}{Fore.RESET}")
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            vulnerable = False
            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    if not input_field.has_attr('type') or input_field['type'].lower() != 'hidden':
                        print(f"{Fore.GREEN}[+] Potential XSS vector found in form: {form.get('action', '')}{Fore.RESET}")
                        vulnerable = True
                        break
            if not vulnerable:
               print(f"{Fore.RED}[-] No obvious XSS vectors found{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning for XSS: {str(e)}{Fore.RESET}")
    
    def scan_sqli(self, url):
        print(f"{Fore.GREEN}[*] Scanning for SQL injection vulnerabilities on {url}{Fore.RESET}")
        test_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*"]
        vulnerable = False
        for payload in test_payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url)
                if any(error in response.text.lower() for error in ['sql syntax', 'mysql', 'ora-', 'syntax error', 'unclosed quotation mark']):
                    print(f"{Fore.GREEN}[+] Potential SQLi vulnerability found with payload: {payload}{Fore.RESET}")
                    vulnerable = True
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing SQLi payload {payload}: {str(e)}{Fore.RESET}")
        if not vulnerable:
            print(f"{Fore.RED}[-] No obvious SQLi vectors found{Fore.RESET}")
    
    def scan_php_links(self, url):
        print(f"{Fore.GREEN}[*] Scanning for PHP links on {url}{Fore.RESET}")
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            php_links = set()
            admin_interfaces = {
                'phpMyAdmin': ['/phpmyadmin/', '/pma/'],
                'Adminer': ['/adminer/', '/mysql-admin/'],
                'WordPress Admin': ['/wp-admin/', '/wp-login.php'],
                'XAMPP': ['/xampp/'],
                'Webmail': ['/webmail/', '/roundcube/']
            }
            for element in soup.find_all(['a', 'form', 'link', 'script', 'iframe']):
                href = None
                if element.name == 'a' and element.has_attr('href'):
                    href = element['href']
                elif element.name == 'form' and element.has_attr('action'):
                    href = element['action']
                elif element.name in ['link', 'script', 'iframe'] and element.has_attr('src'):
                    href = element['src']
                if href:
                    full_url = urljoin(url, href)
                    if '.php' in full_url.lower():
                        php_links.add(full_url)
            for name, paths in admin_interfaces.items():
                for path in paths:
                    admin_url = urljoin(url, path)
                    try:
                        if requests.head(admin_url, timeout=5).status_code == 200:
                            print(f"{Fore.GREEN}[!] Found potential {name} at: {admin_url}{Fore.RESET}")
                    except:
                        continue
            if php_links:
                print(f"{Fore.GREEN}[+] Found {len(php_links)} PHP links:{Fore.RESET}")
                for link in sorted(php_links):
                    print(f"    - {link}")
            else:
                print(f"{Fore.RED}[-] No PHP links found{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error scanning for PHP links: {str(e)}{Fore.RESET}")
    
    def scan_api_keys(self, url):
        print(f"{Fore.GREEN}[*] Scanning for exposed API keys on {url}{Fore.RESET}")
        API_KEY_PATTERNS = {
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
            'Twitter API Key': r'[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
            'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z-]{10,48})',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Heroku API Key': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}'
        }
        try:
            response = requests.get(url)
            found_keys = False
            for key_type, pattern in API_KEY_PATTERNS.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    found_keys = True
                    print(f"{Fore.GREEN}[!] Potential {key_type} Found:{Fore.RESET}")
                    for match in matches[:3]:
                        print(f"    {Fore.YELLOW}{match}{Fore.RESET}")
            if not found_keys:
                print(f"{Fore.RED}[-] No Obvious API Keys Found{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error Scanning For API Keys: {str(e)}{Fore.RESET}")
    
    def scan_lfi(self, url):
        print(f"{Fore.GREEN}[*] Scanning for Local File Inclusion (LFI) vulnerabilities on {url}{Fore.RESET}")
        test_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd"
        ]
        vulnerable = False
        for payload in test_payloads:
            try:
                test_url = f"{url}?file={payload}"
                response = requests.get(test_url)
                if "root:" in response.text:
                    print(f"{Fore.GREEN}[+] Potential LFI vulnerability found with payload: {payload}{Fore.RESET}")
                    vulnerable = True
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing LFI payload {payload}: {str(e)}{Fore.RESET}")
        if not vulnerable:
            print(f"{Fore.RED}[-] No obvious LFI vectors found{Fore.RESET}")

    def crawl_website(self, base_url, max_depth=2):
        print(f"{Fore.GREEN}[*] Crawling {base_url} (max depth: {max_depth}){Fore.RESET}")
        visited = set()
        queue = deque([(base_url, 0)])
        
        while queue:
            url, depth = queue.popleft()
            if depth > max_depth:
                continue
                
            try:
                if url not in visited:
                    visited.add(url)
                    print(f"{Fore.WHITE}[*] Found: {url}{Fore.RESET}")
                    response = requests.get(url, timeout=5)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(url, link['href'])
                        if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                            queue.append((absolute_url, depth + 1))
            except:
                continue

        print(f"{Fore.GREEN}[+] Crawling completed. Found {len(visited)} URLs.{Fore.RESET}")

    def scan_wordpress(self, url):
        print(f"{Fore.GREEN}[*] Scanning for WordPress vulnerabilities on {url}{Fore.RESET}")
        try:
            wp_paths = ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/']
            wp_detected = False
            
            for path in wp_paths:
                target = urljoin(url, path)
                try:
                    response = requests.get(target, timeout=5)
                    if response.status_code == 200:
                        wp_detected = True
                        print(f"{Fore.GREEN}[+] WordPress detected at: {target}{Fore.RESET}")
                        if 'wp-admin' in path:
                            print(f"{Fore.YELLOW}[!] WordPress admin interface found{Fore.RESET}")
                except:
                    continue
            
            if not wp_detected:
                print(f"{Fore.RED}[-] No WordPress detected{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning WordPress: {str(e)}{Fore.RESET}")

    def scan_headers(self, url):
        print(f"{Fore.GREEN}[*] Analyzing HTTP headers for {url}{Fore.RESET}")
        try:
            response = requests.get(url)
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'X-XSS-Protection'
            ]
            
            print(f"\n{Fore.WHITE} - Basic Header Information -{Fore.RESET}")
            print(f"Server: {response.headers.get('Server', 'Not found')}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'Not found')}")
            
            print(f"\n{Fore.WHITE} - Security Headers -{Fore.RESET}")
            missing = 0
            for header in security_headers:
                if header in response.headers:
                    print(f"{Fore.GREEN}[+] {header}: {response.headers[header]}{Fore.RESET}")
                else:
                    print(f"{Fore.RED}[-] Missing security header: {header}{Fore.RESET}")
                    missing += 1
            
            print(f"\n{Fore.WHITE} - Summary - {Fore.RESET}")
            print(f"Security headers present: {len(security_headers) - missing}/{len(security_headers)}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing headers: {str(e)}{Fore.RESET}")

    def detect_tech(self, url):
        print(f"{Fore.GREEN}[*] Detecting technologies on {url}{Fore.RESET}")
        try:
            response = requests.get(url)
            tech = {
                'server': [],
                'framework': [],
                'cms': [],
                'language': [],
                'misc': []
            }
            
            server = response.headers.get('Server', '').lower()
            if 'apache' in server:
                tech['server'].append("Apache")
            elif 'nginx' in server:
                tech['server'].append("Nginx")
            elif 'iis' in server:
                tech['server'].append("Microsoft IIS")
            
            if 'django' in response.text.lower():
                tech['framework'].append("Django")
            if 'laravel' in response.text.lower():
                tech['framework'].append("Laravel")
            if 'express' in response.text.lower():
                tech['framework'].append("Express.js")
            
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                tech['cms'].append("WordPress")
            if 'joomla' in response.text.lower():
                tech['cms'].append("Joomla")
            if 'drupal' in response.text.lower():
                tech['cms'].append("Drupal")
    
            if '.php' in response.text or 'php' in response.headers.get('X-Powered-By', '').lower():
                tech['language'].append("PHP")
            if 'asp.net' in response.headers.get('X-Powered-By', '').lower():
                tech['language'].append("ASP.NET")
        
            if 'react' in response.text:
                tech['framework'].append("React")
            if 'vue' in response.text:
                tech['framework'].append("Vue.js")
            if 'angular' in response.text:
                tech['framework'].append("Angular")

            print(f"\n{Fore.WHITE} - Technology Detection Results -{Fore.RESET}")
            for category, items in tech.items():
                if items:
                    print(f"\n{Fore.YELLOW}{category.capitalize()}:{Fore.RESET}")
                    for item in items:
                        print(f"  {Fore.GREEN}- {item}{Fore.RESET}")
            
            if not any(tech.values()):
                print(f"{Fore.RED}[-] No technologies detected{Fore.RESET}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting technologies: {str(e)}{Fore.RESET}")

   

def show_help():
    print(f"""
{Fore.WHITE}Arachnid Web Scanner - Help Menu{Fore.RESET}

{Fore.WHITE}General Commands:{Fore.RESET}
  banner  name       - Change the banner
  banners            - List available banners
  clear              - Clear the screen
  help               - Show this help menu

{Fore.WHITE}Scanning Commands:{Fore.RESET}
  -s  url  -xss      - Scan for XSS vulnerabilities
  -s  url  -sqli     - Scan for SQL injection
  -s  url  -php      - Scan for PHP links
  -s  url  -api      - Scan for exposed API keys
  -s  url  -lfi      - Scan for LFI vulnerabilities
  -s  url  -crawl    - Web Crawler with Depth Control
  -s  url  -wp       - WordPress vulnerability scanner
  -s  url  -headers  - HTTP headers analyzer
  -s  url  -tech     - Technology detection

{Fore.WHITE}Other Commands:{Fore.RESET}
  exit               - Quit the program
""")

def main():
    scanner = WebScanner()
    scanner.clear_screen()
    print(f"{Fore.WHITE}Type 'help' for available commands{Fore.RESET}")
    
    while True:
        try:
            user_input = input(f"{scanner.user_prompt} ").strip()
            if not user_input:
                continue
            if user_input.lower() == 'exit':
                break
            if user_input.lower() == 'help':
                show_help()
                continue
            if user_input.lower().startswith('banner '):
                banner_name = user_input.split(' ')[1]
                scanner.set_banner(banner_name)
                scanner.show_banner()
                continue
            if user_input.lower() == 'banners':
                print(f"\n{Fore.CYAN}Available banners:{Fore.RESET}")
                for name in BANNERS.keys():
                    print(f"  - {name}")
                print()
                continue
            if user_input.lower() == 'clear':
                scanner.clear_screen()
                continue
            
            parser = argparse.ArgumentParser()
            parser.add_argument('-s', '--site', help='Website to scan')
            parser.add_argument('-d', '--domain', help='Domain for scanning')
            parser.add_argument('-t', '--target', help='Target host for port scanning')
            parser.add_argument('-depth', type=int, default=2, help='Crawl depth (default: 2)')
            parser.add_argument('-xss', action='store_true', help='Scan for XSS')
            parser.add_argument('-sqli', action='store_true', help='Scan for SQLi')
            parser.add_argument('-php', action='store_true', help='Scan for PHP links')
            parser.add_argument('-api', action='store_true', help='Scan for API keys')
            parser.add_argument('-lfi', action='store_true', help='Scan for LFI vulnerabilities')
            parser.add_argument('-crawl', action='store_true', help='Web Crawler with Depth Control')
            parser.add_argument('-wp', action='store_true', help='WordPress scanner')
            parser.add_argument('-headers', action='store_true', help='HTTP headers analyzer')
            parser.add_argument('-tech', action='store_true', help='Technology detection')
            parser.add_argument('-html', action='store_true', help='html report')
            parser.add_argument('-json', action='store_true', help='Generate JSON report')

            try:
                args = parser.parse_args(user_input.split())
                if args.site:
                    if args.xss:
                        scanner.scan_xss(args.site)
                    if args.sqli:
                        scanner.scan_sqli(args.site)
                    if args.php:
                        scanner.scan_php_links(args.site)
                    if args.api:
                        scanner.scan_api_keys(args.site)
                    if args.lfi:
                        scanner.scan_lfi(args.site)
                    if args.crawl:
                        scanner.crawl_website(args.site, args.depth)
                    if args.wp:
                        scanner.scan_wordpress(args.site)
                    if args.headers:
                        scanner.scan_headers(args.site)
                    if args.tech:
                        scanner.detect_tech(args.site)
                    if args.html:
                        scanner.generate_html_report(args.site)
                    if args.json:
                        scanner.generate_json_report(args.site)
                    if not any([args.xss, args.sqli, args.php, args.api, args.lfi, args.crawl, 
                               args.wp, args.headers, args.tech, args.html, args.json]):
                        print(f"{Fore.RED}[!] Please specify at least one scan type{Fore.RESET}")
                elif args.domain:
                    if args.sub:
                        scanner.scan_subdomains(args.domain)
                    if args.dns:
                        scanner.dns_lookup(args.domain)
                    if not any([args.sub, args.dns]):
                        print(f"{Fore.RED}[!] Please specify either -sub or -dns for domain scanning{Fore.RESET}")
                elif args.target:
                    if args.ports:
                        scanner.port_scan(args.target, args.ports)
                    else:
                        scanner.port_scan(args.target)
                else:
                    print(f"{Fore.RED}[!] Invalid command. Type 'help' for available commands{Fore.RESET}")
            except SystemExit:
                continue
        except KeyboardInterrupt:
            print(f"\n{Fore.WHITE}Use 'exit' to quit{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Fore.RESET}")

if __name__ == "__main__":
    main()
