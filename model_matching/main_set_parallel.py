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
apps_per_run = 200

def analyze_malicious(package_list, similarities_found, similarities_found_by_perms, similarities_found_by_chains):
	count_apps = 0
	for package_name in package_list:
		count_apps += 1
		print(str(os.getpid()) + ' Processing ' + package_name + ' ( ' + str(count_apps) + ' / ' + str(len(package_list)) + ' )')
		try:
			andr_a = APK(package_name)
			andr_d = dvm.DalvikVMFormat( andr_a.get_dex() )

			perms = permission_matching.get_perm_vector(andr_a)
			similar_list = permission_matching.get_similar(perms)
			similarities_found_by_perms[package_name] = similar_list

			api = api_matching.get_used_api(andr_d)
			similar_api_list = api_matching.get_similar_api(api, similar_list)
			similarities_found[package_name] = similar_api_list

			similar_api_chains_list = api_chain_matching.get_similar(andr_a, andr_d, similar_api_list)
			similarities_found_by_chains[package_name] = similar_api_chains_list
		except:
			print 'Failed to decompile app'
			continue

def process_list_apps(list_apps_f, similarities_found_by_perms_f, similarities_found_f, similarities_found_by_chains_f, tag):
	#Already counted part
	try:
		f = open(similarities_found_by_perms_f, 'r')
		counted_similarities_found_by_perms = json.loads(f.read())
		f.close()
	except:
		counted_similarities_found_by_perms = {}

	try:
		f = open(similarities_found_f, 'r')
		counted_similarities_found = json.loads(f.read())
		f.close()
	except:
		counted_similarities_found = {}

	try:
		f = open(similarities_found_by_chains_f, 'r')
		counted_similarities_found_by_chains = json.loads(f.read())
		f.close()
	except:
		counted_similarities_found_by_chains = {}

	package_list = []
	analyzed_apps = list_apps_f
	f = open(analyzed_apps, 'r')

	for line in f:
		package_name = line[:-1]
		if not package_name in counted_similarities_found:
			package_list.append(package_name)
	print len(package_list), tag, 'samples to analyze'

	f.close()

	manager = Manager()
	similarities_found = manager.dict()
	similarities_found_by_perms = manager.dict()
	similarities_found_by_chains = manager.dict()

	j = 0
	while j * apps_per_run < len(package_list):
		similarities_found = manager.dict()
		similarities_found_by_perms = manager.dict()
		similarities_found_by_chains = manager.dict()

		processes = []
		for i in range(num_processes):
			list_analysis = manager.list(package_list[(j + i) * apps_per_run : (j + i + 1) * apps_per_run if (j + i + 1) * apps_per_run < len(package_list) else len(package_list)])
			p = Process(target=analyze_malicious, args=(list_analysis, similarities_found, \
				similarities_found_by_perms, similarities_found_by_chains))
			processes.append(p)
			p.start()
			if (j + i + 1) * apps_per_run >= len(package_list):
				break
		for p in processes:
			p.join()
		counted_similarities_found_by_perms.update(dict(similarities_found_by_perms))
		counted_similarities_found.update(dict(similarities_found))
		counted_similarities_found_by_chains.update(dict(similarities_found_by_chains))

		f = open(similarities_found_by_perms_f, 'w')
		f.write(json.dumps(counted_similarities_found_by_perms, indent=4, separators=(',', ': ')))
		f.close()

		f = open(similarities_found_f, 'w')
		f.write(json.dumps(counted_similarities_found, indent=4, separators=(',', ': ')))
		f.close()

		f = open(similarities_found_by_chains_f, 'w')
		f.write(json.dumps(counted_similarities_found_by_chains, indent=4, separators=(',', ': ')))
		f.close()
		j += num_processes

	count_m = 0
	for package_name in counted_similarities_found_by_chains:
		if counted_similarities_found_by_chains[package_name] != []:
			count_m += 1
	print 'Identified as malicious in', tag, 'tests', count_m, '/', len(counted_similarities_found_by_chains.keys())

if __name__ == "__main__":
#Malicious part
	process_list_apps('malware_for_analysis.txt', 'similarities_found_by_perms_m.json', 'similarities_found_m.json', 'similarities_found_by_chains_m.json', 'malicious')

#Benign part
	process_list_apps('benign_for_analysis.txt', 'similarities_found_by_perms_b.json', 'similarities_found_b.json', 'similarities_found_by_chains_b.json', 'benign')
