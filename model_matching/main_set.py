#!/usr/bin/python
import permission_matching
import api_matching
import json

analyzed_apps = 'malware_for_analysis.txt'
f = open(analyzed_apps, 'r')
total_apps_m = sum(1 for line in open(analyzed_apps))

similarities_found_m = {}
similarities_found_by_perms_m = {}

count_apps = 0
malicious_m = 0
malicious_perms_m = 0
for line in f:
	package_name = line[:-1]
	count_apps += 1
	print 'Processing', package_name, '(', count_apps, ' / ', total_apps_m, ')'
	
	perms = permission_matching.get_perm_vector(package_name)
	similar_list = permission_matching.get_similar(perms)
	if len(similar_list) != 0:
		malicious_perms_m += 1
	similarities_found_by_perms_m[package_name] = similar_list

	api = api_matching.get_used_api(package_name)
	similar_api_list = api_matching.get_similar_api(api, similar_list)

	if len(similar_api_list) != 0:
		malicious_m += 1
		print 'malicious', len(similar_api_list)
	else:
		print 'falsenegative'
	similarities_found_m[package_name] = similar_api_list

f.close()

analyzed_apps = 'benign_for_analysis.txt'
f = open(analyzed_apps, 'r')
total_apps_b = sum(1 for line in open(analyzed_apps))

similarities_found_b = {}
similarities_found_by_perms_b = {}

count_apps = 0
malicious_b = 0
malicious_perms_b = 0
for line in f:
	package_name = line[:-1]
	count_apps += 1
	print 'Processing', package_name, '(', count_apps, ' / ', total_apps_b, ')'

	perms = permission_matching.get_perm_vector(package_name)
	similar_list = permission_matching.get_similar(perms)
	if len(similar_list) != 0:
		malicious_perms_b += 1

	similarities_found_by_perms_b[package_name] = similar_list
	api = api_matching.get_used_api(package_name)
	similar_api_list = api_matching.get_similar_api(api, similar_list)

	if len(similar_api_list) != 0:
		malicious_b += 1
		print 'malicious', len(similar_api_list)
		print 'falsepositive'
	similarities_found_b[package_name] = similar_api_list

f.close()

print 'By permissions:'
print 'malicious:', malicious_perms_m, '/', total_apps_m
print 'benign:', malicious_perms_b, '/', total_apps_b

print 'By API:'
print 'malicious:', malicious_m, '/', total_apps_m
print 'benign:', malicious_b, '/', total_apps_b

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

