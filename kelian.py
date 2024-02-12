# basic Recon tool
import argparse
import whois
import dns.resolver
import socket
import time
import requests
import sys
import threading

ip = ""
parser = argparse.ArgumentParser(description='(KELIAN) This is a Information gathering tool. Coded by RITESH KUMAR')

# For banner grabbing function
def scan_port(port, host_ip):
	try:
		status = False
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		s.settimeout(1.5)
		s.connect((host_ip, port)) 
		try: 
			banner = s.recv(1024).decode() 
			print("port {} is open with banner {}".format(port, banner)) 
		except:
			print(f"port {port} is open ") 
	except:
		pass

def Scanner(url, whois_lookup, geo_ip_lookup, dns_lookup, cname_lookup, mx_lookup,txt_lookup, banner_grabing):
	global ip
	initial_time = time.perf_counter()
	print("\n"+"-"*50+"Scanning"+"-"*50)
	print(f"\n Host : {url}")
	try:
		ip = socket.gethostbyname(url)
		print(f" Ip : {ip}")
	except Exception as e:
		print("\n"+"-"*108)
		print("\n ERROR OCCURED (may be your url is not valid or incorrect.)")
		sys.exit()
	

	if not whois_lookup and not geo_ip_lookup and not geo_ip_lookup and not dns_lookup and not cname_lookup and not mx_lookup and not txt_lookup and not banner_grabing:
		print("\nFLAG IS REQUIRED FOR FURTHER PROCESSING. Example: practice.py www.example.com -w")

	# Perform the WHOIS lookup
	if whois_lookup:
		print("\n[+] Information gathering - whois lookup")
		print("-"*50)
		try:
			whois_lookup = whois.whois(url)
			for keys in dict(whois_lookup).keys():
				if isinstance(whois_lookup[keys], list):
					print(f"\n{keys} :-")
					for key in whois_lookup[keys]:
						print(key)
				else:
					print(f"\n{keys} :- {whois_lookup[keys]}")
		except Exception as e:
			print(e)

	# for geo ip lookup
	if geo_ip_lookup:	
		print("\n[+] Information gathering - geo ip lookup")
		print("-"*50)
		res = requests.get(f"https://ipinfo.io/{ip}/json")
		for key in res.json().keys():
			if key == "readme":
				break
			print(f"{key} :- {res.json()[key]}")

	# For dns lookup
	if dns_lookup:
		print("\n[+] Information gathering - dns lookup")
		print("-"*50)
		try:
			result = dns.resolver.resolve(url, 'A')
			for ip_address in result:
				print(f'The IP address of {url} is {ip_address.address}')
		except dns.exception.DNSException as e:
			print(f'Error: {e}')

	# For cname lookup
	if cname_lookup:
		print("\n[+] Information gathering - cname lookup")
		print("-"*50)
		try:
			result = dns.resolver.resolve(url, 'CNAME')
			for cname_record in result:
				print(f'The CNAME record for {url} is {cname_record.target}')
		except dns.exception.DNSException as e:
			print(f'Error: {e}')

	# For mx lookup
	if mx_lookup:
		print("\n[+] Information gathering - mx lookup")
		print("-"*50)
		try:
			result = dns.resolver.resolve(url, 'MX')
			for mx_record in result:
				print(f'The MX record for {url} is {mx_record.exchange} with priority {mx_record.preference}')
		except dns.exception.DNSException as e:
			print(f'Error: {e}')

	# For txt lookup
	if txt_lookup:
		print("\n[+] Information gathering - txt lookup")
		print("-"*50)
		try:
			result = dns.resolver.resolve(url, 'TXT')
			for txt_record in result:
				print(f'The TXT record for {url} is {txt_record.strings}')
		except dns.exception.DNSException as e:
			print(f'Error: {e}')

	if banner_grabing:
		print("\n[+] Information gathering - banner grabing also port scanning")
		print("-"*50)
		try:
			for i in range(0,65535): 
				print(f"SCANNING: ", end="\r")
				thread = threading.Thread(target=scan_port, args=[i,ip]) 
				thread.start()
		except KeyboardInterrupt:
			print("\n\nCtrl+C pressed. Exiting the program.") 
     	

	# Ending fucntionality
	end_time = time.perf_counter()
	print("\n"+"-"*50)
	print(f"Finished in {end_time-initial_time}s")

if __name__ == '__main__':
	# Add command line arguments
	parser.add_argument("url", help="url of the target host")
	parser.add_argument("-w", "--whois_scan",action="store_true", help="Perform whois lookup scan on target host")
	parser.add_argument("-g", "--geo_ip_lookup", action="store_true", help="Perform geo ip lookup on target host")
	parser.add_argument("-d", "--dns_lookup", action="store_true", help="Perform dns lookup on target host")
	parser.add_argument("-c", "--cname_lookup", action="store_true", help="Perform cname lookup on target host")
	parser.add_argument("-m", "--mx_lookup", action="store_true", help="Perform mx lookup on target host")
	parser.add_argument("-t", "--txt_lookup", action="store_true", help="Perform txt lookup on target host")
	parser.add_argument("-b", "--banner_grabing", action="store_true",help="Perform banner grabbing and port scanning recon on target host")
	# parser.add_argument("-o", "--output" ,help="timepass optinal", default="helOp")
			
	# Parse the arguments
	args = parser.parse_args()

	Scanner(args.url, args.whois_scan, args.geo_ip_lookup, args.dns_lookup, args.cname_lookup, args.mx_lookup, args.txt_lookup,args.banner_grabing)