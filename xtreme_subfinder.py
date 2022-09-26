#!/usr/bin/env python3

import subprocess
from termcolor import colored
import os
import threading
import argparse
import signal,sys
import re
import datetime,configparser

def banner(url):


	w ="""

  	   _  ____                                         __    _____           __         
	  | |/ / /_________  ____ ___  ___     _______  __/ /_  / __(_)___  ____/ /__  _____
	  |   / __/ ___/ _ \/ __ `__ \/ _ \   / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
	 /   / /_/ /  /  __/ / / / / /  __/  (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
	/_/|_\__/_/   \___/_/ /_/ /_/\___/  /____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/     
	"""                                                                                    



 
	x = "	+-----------------------------------------------------------------------------+"     
	y = "				           			~~Twitter: Killeroo7p && Tanujbaware\n\n"

	z = """

	 URL     :"""+url+"""
	 Time    :"""+str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))+"""

	"""

	print(colored(w,'blue'))
	print(colored(x,'red'))
	print(colored(y,'green'))
	print(colored(z,'blue'))

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url',dest='url',required=True,help="Specify URL")
	parser.add_argument('-o','--output',dest='output',help="Output Location")
	parser.add_argument('-g','--gowitness',dest='run_gowitness', action='store_true',help="Run Gowitness")
	parser.add_argument('-a','--amass',dest='amass', action='store_true',help="Ignore Amass")
	parser.add_argument('-k','--keep',dest='keep_individual_files',action='store_true',help="Keep each Subdomain tool result separtely ")
	parser.add_argument('-ls','--loose-scope',dest='loose_scope',action='store_true',help="Do not remove out of scope targets")

	args = parser.parse_args()
	return args


def signal_handler(signal, frame):
  print(colored("\n\nExitting.... BYE BYE\n","cyan"))
  sys.exit(0)


def create_unique_directory(url):
	directory = f"subs_"+url+"{}"
	counter = 0
	while os.path.exists(directory.format(counter)):
	    counter += 1
	directory = directory.format(counter)
	os.mkdir(directory)
	os.chdir(directory)
	return directory

def filter_duplicate_domains(x):
  return list(dict.fromkeys(x))

def amass(url):
	print(colored("[+] Scanning For Subdomains with Amass",'green'))
	amass_cmd = f"amass enum -d {url} -o amass_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(amass_cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Amass Scanning Completed",'yellow'))

def sublister(url):
	print(colored("[+] Scanning For Subdomains with Sublist3r",'green'))
	sublister_cmd = f"sublist3r -d {url} -o sublister_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(sublister_cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Sublist3r Scanning Completed",'yellow'))

def assetfinder(url):
	print(colored("[+] Scanning For Subdomains with AssetFinder",'green'))
	asset_cmd = f"assetfinder {url} --subs-only > assetfinder_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(asset_cmd,shell=True,stdout=devnull)
	print(colored("[+] AssetFinder Scanning Completed",'yellow'))

def subfinder(url): 
	print(colored("[+] Scanning For Subdomains with Subfinder",'green'))
	subfinder_cmd = f"subfinder -d {url} -o subfinder_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(subfinder_cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Subfinder Scanning Completed",'yellow'))

def github_subdomains(url,GITTOKEN):	
	print(colored("[+] Scanning For Subdomains with github-subdomains",'green'))
	cmd_github_subdomains = f"github-subdomains.py -t {GITTOKEN} -d {url} > github_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_github_subdomains,shell=True,stdout=devnull)
	print(colored("[+] Github-subdomains Scanning Completed",'yellow'))

def shosubgo(url,SHODANAPI):
	print(colored("[+] Scanning For Subdomains with shosubgo",'green'))
	cmd_shosubgo = f"shosubgo_linux -d {url} -s {SHODANAPI} > shosubgo_subs_files"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_shosubgo,shell=True,stdout=devnull)
	print(colored("[+] Shosubgo Scanning Completed",'yellow'))


def filter_subs(url):
		all_subs = []

		try:			
			with open ('amass_subs_file','r') as amass_subs:
				for line in amass_subs:
					all_subs.append(line)
		except:
			pass

		try:                                                             #try block coz sometimes sublister gives error which breaks the entire program
			with open ('sublister_subs_file','r') as sublister_subs:
				for line in sublister_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('assetfinder_subs_file','r') as assetfinder_subs:
				for line in assetfinder_subs:
					all_subs.append(line)
		except:
			pass


		try:			
			with open ('subfinder_subs_file','r') as subfinder_subs:
				for line in subfinder_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('github_subs_file','r') as github_subs:
				for line in github_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('shosubgo_subs_files','r') as shosubgo_subs:
				for line in shosubgo_subs:
					all_subs.append(line)
		except:
			pass


		filtered = filter_duplicate_domains(all_subs)
		with open ('subdomain.txt','w') as all_subs_file:
			for line in filtered:
				all_subs_file.write(line)

		print(colored("[+] Removed Duplicate Domains",'yellow'))

		##Remove Out Of Scope Subdomains
		if not get_args().loose_scope:
			subprocess.call(f'cat subdomain.txt | grep {url} > subdomains.txt',shell=True)
			os.remove("subdomain.txt")
		else:
			os.rename("subdomain.txt","subdomains.txt")


		if not get_args().keep_individual_files:

			try:
				os.remove('amass_subs_file')
			except:
				pass

			try:
				os.remove('assetfinder_subs_file')
				os.remove('subfinder_subs_file')
				os.remove('shosubgo_subs_files')
				os.remove('github_subs_file')
				os.remove('sublister_subs_file')
			except:
				pass


def http_probe():
	file = "httprobe_subdomains.txt"
	print(colored("[+] Started HttProbe on subdomains.txt","green"))
	cmd = "cat subdomains.txt | httprobe > " + file
	subprocess.call(cmd,shell=True)
	print(colored("[+] Httprobe Completed",'yellow'))


def gowitness():
	print(colored("[+] Started Gowitness for Visual Recon","green"))
	cmd = "gowitness file -f httprobe_subdomains.txt"
	subprocess.call(cmd,shell=True)
	print(colored("[+] Gowitness Completed",'yellow'))


def main():
	url = get_args().url
	banner(url)

	if "http" in url:
		print("Enter URL in format domain.tld")
		exit(0)

	directory=create_unique_directory(url)
	signal.signal(signal.SIGINT, signal_handler)

###
	temppath = os.path.realpath(__file__).split('/')[:-1]
	configParser = configparser.RawConfigParser()
	configFilePath = ("/".join(temppath)) +"/keys.config"
	configParser.read(configFilePath)

	SHODAN_API = configParser.get('KEYS', 'shodanAPI')
	GITTOKEN = configParser.get('KEYS', 'githubAPI')
###

	if get_args().amass:
		t_amass = threading.Thread(target=amass,name="t_amass",args=([url]))
		t_amass.start()

	t_sublister = threading.Thread(target=sublister,name="t_sublister",args=([url]))
	t_sublister.start()

	t_assetfinder = threading.Thread(target=assetfinder,name="t_assetfinder",args=([url]))
	t_assetfinder.start()

	t_subfinder = threading.Thread(target=subfinder,name="t_subfinder",args=([url]))
	t_subfinder.start()

	if len(SHODAN_API) > 0:
		t_shosubgo = threading.Thread(target=shosubgo,name="t_shosubgo",args=(url,SHODAN_API))
		t_shosubgo.start()

	if len(GITTOKEN) > 0:
		t_github_subs = threading.Thread(target=github_subdomains,name="t_github_subs",args=(url,GITTOKEN))
		t_github_subs.start()


	t_sublister.join()
	t_assetfinder.join()
	t_subfinder.join()

	if get_args().amass:
		t_amass.join()

	if len(SHODAN_API) > 0:
		t_shosubgo.join()

	if len(GITTOKEN) > 0:
		t_github_subs.join()

	filter_subs(url)
	http_probe()

	if get_args().run_gowitness:
		gowitness()

	print(colored("\n[+] Subdomain Scanning Completed",'cyan'))
	print(colored(f"\n[+] Output Saved to {directory}",'yellow'))

main()

#TESTING SHOSUBHO AND GITHUBSUBDOMAINS___________________________________#
def shosubgo(url,SHODANAPI):
	print(colored("[+] Scanning For Subdomains with Shosubgo",'green'))
	cmd_shosubgo = f"shosubgo_linux -d {url} -s {SHODANAPI} > shosubgo_subs_files"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_shosubgo,shell=True,stdout=devnull)
	print(colored("[+] Shosubgo Scanning Completed",'yellow'))

def test():
	url = get_args().url
	banner(url)

	if "http" in url:
		print("Enter URL in format domain.tld")
		exit(0)

###
	temppath = os.path.realpath(__file__).split('/')[:-1]
	configParser = configparser.RawConfigParser()
	configFilePath = ("/".join(temppath)) +"/key.config"
	configParser.read(configFilePath)

	SHODAN_API = configParser.get('KEYS', 'shodanAPI')
	GITTOKEN = configParser.get('KEYS', 'githubAPI')
	print(SHODAN_API)
###
	shosubgo(url,SHODAN_API)

# test()
