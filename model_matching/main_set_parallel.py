#!/usr/bin/python
import sys
sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
import androlyze as anz

import permission_matching
import api_matching
import api_chain_matching
api_chain_matching.work_until_first_match = True

import json
from multiprocessing import Process, Manager
import copy
import math
import os

num_processes = 4

def analyze_malicious(package_list, similarities_found, similarities_found_by_perms, similarities_found_by_chains):
	count_apps = 0
	for package_name in package_list:
		count_apps += 1
		print(str(os.getpid()) + ' Processing ' + package_name + ' ( ' + str(count_apps) + ' / ' + str(len(package_list)) + ' )')
		try:
			andr_a = APK(package_name)
			andr_d = dvm.DalvikVMFormat( andr_a.get_dex() )
			#print 'Failed to decompile app'

			perms = permission_matching.get_perm_vector(andr_a)
			similar_list = permission_matching.get_similar(perms)
			similarities_found_by_perms[package_name] = similar_list

			api = api_matching.get_used_api(andr_d)
			similar_api_list = api_matching.get_similar_api(api, similar_list)
			similarities_found[package_name] = similar_api_list

			similar_api_chains_list = api_chain_matching.get_similar(andr_a, andr_d, similar_api_list)
			similarities_found_by_chains[package_name] = similar_api_chains_list
		except:
			continue

if __name__ == "__main__":
#Malicious part
	package_list = []
	analyzed_apps = 'malware_for_analysis.txt'
	f = open(analyzed_apps, 'r')

	for line in f:
		package_name = line[:-1]
		package_list.append(package_name)

	f.close()

	manager = Manager()
	similarities_found = manager.dict()
	similarities_found_by_perms = manager.dict()
	similarities_found_by_chains = manager.dict()
	processes = []
	for i in range(num_processes):
		list_analysis = manager.list(package_list[int(round(len(package_list) * i / num_processes, 0)) : int(round(len(package_list) * (i + 1) / num_processes, 0))])
		p = Process(target=analyze_malicious, args=(list_analysis, similarities_found, \
			similarities_found_by_perms, similarities_found_by_chains))
		processes.append(p)
		p.start()
	for p in processes:
		p.join()

	f = open('similarities_found_by_perms_m.json', 'w')
	simple_dict = dict(similarities_found_by_perms)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	f = open('similarities_found_m.json', 'w')
	simple_dict = dict(similarities_found)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	f = open('similarities_found_by_chains_m.json', 'w')
	simple_dict = dict(similarities_found_by_chains)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	count_m = 0
	for package_name in simple_dict:
		if simple_dict[package_name] != []:
			count_m += 1
	print 'Identified as malicious in malicious tests', count_m, '/', len(simple_dict.keys())


#Benign part
	package_list = []
	analyzed_apps = 'benign_for_analysis.txt'
	f = open(analyzed_apps, 'r')

	for line in f:
		package_name = line[:-1]
		package_list.append(package_name)

	f.close()

	similarities_found = manager.dict()
	similarities_found_by_perms = manager.dict()
	similarities_found_by_chains = manager.dict()
	processes = []
	for i in range(num_processes):
		list_analysis = manager.list(package_list[int(round(len(package_list) * i / num_processes, 0)) : int(round(len(package_list) * (i + 1) / num_processes, 0))])
		p = Process(target=analyze_malicious, args=(list_analysis, similarities_found, \
			similarities_found_by_perms, similarities_found_by_chains))
		processes.append(p)
		p.start()
	for p in processes:
		p.join()

	f = open('similarities_found_by_perms_b.json', 'w')
	simple_dict = dict(similarities_found_by_perms)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	f = open('similarities_found_b.json', 'w')
	simple_dict = dict(similarities_found)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	f = open('similarities_found_by_chains_b.json', 'w')
	simple_dict = dict(similarities_found_by_chains)
	f.write(json.dumps(simple_dict, indent=4, separators=(',', ': ')))
	f.close()

	count_m = 0
	for package_name in simple_dict:
		if simple_dict[package_name] != []:
			count_m += 1
	print 'Identified as malicious in benign tests', count_m, '/', len(simple_dict.keys())
