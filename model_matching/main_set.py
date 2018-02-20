#!/usr/bin/python
import sys
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

import permission_matching
import api_matching
import api_chain_matching
api_chain_matching.work_until_first_match = True

sys.path.append('../api_chains')
import api_chains

import json

analyzed_apps = 'malware_for_analysis.txt'
f = open(analyzed_apps, 'r')
total_apps_m = sum(1 for line in open(analyzed_apps))

similarities_found_m = {}
similarities_found_by_perms_m = {}
similarities_found_by_chains_m = {}

count_apps = 0
malicious_m = 0
malicious_perms_m = 0
malicious_chains_m = 0
for line in f:
	package_name = line[:-1]
	count_apps += 1
	print 'Processing', package_name, '(', count_apps, ' / ', total_apps_m, ')'
	try:
		andr_a = APK(package_name)
		andr_d = dvm.DalvikVMFormat( andr_a.get_dex() )
	except:
		print 'Failed to decompile app'
		continue
	
	perms = permission_matching.get_perm_vector(andr_a)
	similar_list = permission_matching.get_similar(perms)
	if len(similar_list) != 0:
		malicious_perms_m += 1
	similarities_found_by_perms_m[package_name] = similar_list

	api = api_matching.get_used_api(andr_d)
	similar_api_list = api_matching.get_similar_api(api, similar_list)
	if len(similar_api_list) != 0:
		malicious_m += 1
	similarities_found_m[package_name] = similar_api_list

	similar_api_chains_list = api_chain_matching.get_similar_short(andr_a, andr_d, similar_api_list)
	if len(similar_api_chains_list) != 0:
		malicious_chains_m += 1
		print 'malicious', similar_api_chains_list
	else:
		print 'falsenegative'
	similarities_found_by_chains_m[package_name] = similar_api_chains_list

f.close()

analyzed_apps = 'benign_for_analysis.txt'
f = open(analyzed_apps, 'r')
total_apps_b = sum(1 for line in open(analyzed_apps))

similarities_found_b = {}
similarities_found_by_perms_b = {}
similarities_found_by_chains_b = {}

count_apps = 0
malicious_b = 0
malicious_perms_b = 0
malicious_chains_b = 0
for line in f:
	package_name = line[:-1]
	count_apps += 1
	print 'Processing', package_name, '(', count_apps, ' / ', total_apps_b, ')'
	try:
		andr_a = APK(package_name)
		andr_d = dvm.DalvikVMFormat( andr_a.get_dex() )
	except:
		print 'Failed to decompile app'
		continue

	perms = permission_matching.get_perm_vector(andr_a)
	similar_list = permission_matching.get_similar(perms)
	if len(similar_list) != 0:
		malicious_perms_b += 1
	similarities_found_by_perms_b[package_name] = similar_list

	api = api_matching.get_used_api(andr_d)
	similar_api_list = api_matching.get_similar_api(api, similar_list)
	if len(similar_api_list) != 0:
		malicious_b += 1
	similarities_found_b[package_name] = similar_api_list

	similar_api_chains_list = api_chain_matching.get_similar_short(andr_a, andr_d, similar_api_list)
	if len(similar_api_chains_list) != 0:
		malicious_chains_b += 1
		print 'malicious', similar_api_list
		print 'falsepositive'
	similarities_found_by_chains_b[package_name] = similar_api_chains_list

f.close()

print 'Identified as malicious by permissions:'
print 'malicious:', malicious_perms_m, '/', total_apps_m
print 'benign:', malicious_perms_b, '/', total_apps_b

print 'Identified as malicious by API:'
print 'malicious:', malicious_m, '/', total_apps_m
print 'benign:', malicious_b, '/', total_apps_b

print 'Identified as malicious by API chains:'
print 'malicious:', malicious_chains_m, '/', total_apps_m
print 'benign:', malicious_chains_b, '/', total_apps_b

f = open('similarities_found_m.json', 'w')
f.write(json.dumps(similarities_found_m, indent=4, separators=(',', ': ')))
f.close()

f = open('similarities_found_b.json', 'w')
f.write(json.dumps(similarities_found_b, indent=4, separators=(',', ': ')))
f.close()

f = open('similarities_found_by_perms_m.json', 'w')
f.write(json.dumps(similarities_found_by_perms_m, indent=4, separators=(',', ': ')))
f.close()

f = open('similarities_found_by_perms_b.json', 'w')
f.write(json.dumps(similarities_found_by_perms_b, indent=4, separators=(',', ': ')))
f.close()

f = open('similarities_found_by_chains_m.json', 'w')
f.write(json.dumps(similarities_found_by_chains_m, indent=4, separators=(',', ': ')))
f.close()

f = open('similarities_found_by_chains_b.json', 'w')
f.write(json.dumps(similarities_found_by_chains_b, indent=4, separators=(',', ': ')))
f.close()

