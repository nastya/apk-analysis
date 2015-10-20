#!/usr/bin/python
import permission_matching
import api_matching
import api_chains
import sys
sys.path.append('../')
import interesting_api

import os, fnmatch

samples_dir = "../../drebin_samples"
def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result

if (len(sys.argv) > 1):
	package_name = sys.argv[1]
else:
	print 'Usage:'
	print sys.argv[0], 'apkfile'
	sys.exit()

perms = permission_matching.get_perm_vector(package_name)
similar_list = permission_matching.get_similar(perms)
if similar_list != []:
	print 'Similar malware by permissions:'
	for x in similar_list:
		print x
	print '___________________________________________________________________'

api = api_matching.get_used_api(package_name)
similar_api_list = api_matching.get_similar_api(api, similar_list)

if len(similar_api_list) != 0:
	print 'Similar malware by API:'
	for x in similar_api_list:
		print x
	print '___________________________________________________________________'
else:
	print 'No API-similarities with malware models'

api_chains_app = api_chains.get_api_chains(package_name)
if (api_chains_app == None):
	print 'Failed to obtain chains of app', package_name
	sys.exit(0)

for sample in similar_api_list:
	found_fls = find(sample, samples_dir)
	sample_full_path = found_fls[0] if len(found_fls) > 0 else None
	if sample_full_path == None:
		print 'Not found: ', sample
	api_chains_sample = api_chains.get_api_chains(sample_full_path)
	if (api_chains_sample == None):
		print 'Failed to decompile sample', sample_full_path
		continue
	mal_a = sum((1 if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample)
	mal_b = sum((len(x.chain) if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample)
	common_chains = []
	a,b,c,d = api_chains.compare_api_chains(api_chains_app, api_chains_sample, common_chains)

	if (a >= api_chains.threshold_total_common_chains and b >= api_chains.threshold_total_common_length) or \
		(c >= 2) or (c >= 1 and d >= 1) or \
		(d >= 2 and b >= api_chains.threshold_total_common_length) or \
		(mal_a != 0 and mal_b != 0 and a * 1.0 / mal_a >= api_chains.threshold_identical_num_chains and b * 1.0 / mal_b >= api_chains.threshold_identical_len_chains):
		print 'Common API chains with', sample_full_path
		for i in range(0, len(common_chains)):
			for j in range(0, len(common_chains[i].chain)):
				if common_chains[i].chain[j] in interesting_api.interesting_api:
					common_chains[i].chain[j] = '*******************************************' + common_chains[i].chain[j]

		for i in range(0, len(common_chains)):
			print 'Root1:', common_chains[i].root
			print 'Root2:', common_chains[i].root2
			for j in range(0, len(common_chains[i].chain)):
				print common_chains[i].chain[j]
			print '-------------------------------------------------------------------'
		print '___________________________________________________________________'
		

