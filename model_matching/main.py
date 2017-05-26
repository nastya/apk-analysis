#!/usr/bin/python
import sys
sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

import permission_matching
import api_matching

import api_chain_matching
sys.path.append('../api_chains')
import api_chains
import detectLibPackages

sys.path.append('../')
import interesting_api
import thresholds

samples_dir = "../../drebin_samples"
import os, fnmatch
import time

def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result

if (len(sys.argv) > 1):
	package_name = sys.argv[1]
	if len(sys.argv) > 3 and sys.argv[2] == '-b':
		api_chains.bloom_f = True
		detectLibPackages.set_bloom_filter(sys.argv[3])
else:
	print 'Usage:'
	print sys.argv[0], 'apkfile [-b filter_file]'
	print '    -b option enables filtering library packages using bloom filter with hashes,'
	print '     by default this filtering is done via string matching.'
	sys.exit()

try:
	time_s = time.time()
	andr_a = APK(package_name)
	andr_d = dvm.DalvikVMFormat( andr_a.get_dex() )
	time_decompile = time.time() - time_s
except:
	print 'Failed to decompile app'
	sys.exit()

time_s = time.time()
perms = permission_matching.get_perm_vector(andr_a)
similar_list = permission_matching.get_similar(perms)
if similar_list != []:
	print 'Similar malware by permissions:'
	for x in similar_list:
		print x
	print '___________________________________________________________________'
time_perms = time.time() - time_s

time_s = time.time()
api = api_matching.get_used_api(andr_d)
similar_api_list = api_matching.get_similar_api(api, similar_list)

if len(similar_api_list) != 0:
	print 'Similar malware by API:'
	for x in similar_api_list:
		print x
	print '___________________________________________________________________'
else:
	print 'No API-similarities with malware models'
time_api = time.time() - time_s

time_s = time.time()
api_chains_app = api_chains.get_api_chains(andr_a, andr_d)
if (api_chains_app == None):
	print 'Failed to obtain chains of app', package_name
	sys.exit(0)
time_getting_chains = time.time() - time_s


api_chains_app_dict = {}
for api_chain in api_chains_app:
	api_chains_app_dict[api_chain.root] = api_chain.chain

is_malicious = False

time_s = time.time()
for sample in similar_api_list:
	if (not sample in api_chain_matching.api_chain_model.malw_api_chain_models):
		continue
	api_chains_sample_dict = api_chain_matching.api_chain_model.malw_api_chain_models[sample]

	api_chains_sample_list = api_chain_matching.api_chain_model.malw_api_chain_models_in_lists[sample]
	if (api_chains_sample_list == []): #ignoring empty malware models if any
			continue
	
	mal_a = sum((1 if len(x.chain) >= thresholds.api_chains_minimum_length else 0) for x in api_chains_sample_list)
	mal_b = sum((len(x.chain) if len(x.chain) >= thresholds.api_chains_minimum_length else 0) for x in api_chains_sample_list)
	common_chains = []
	a,b,c,d = api_chains.compare_api_chains(api_chains_app, api_chains_sample_list, common_chains)
	print a, b, c, d, mal_a, mal_b, 'Sample: ', sample

	flag_similar = False
	if (a >= thresholds.api_chains_total_common_chains and b >= thresholds.api_chains_total_common_length) or \
		(c >= 2) or (c >= 1 and d >= 1) or \
		(d >= 1 and b >= thresholds.api_chains_total_common_length) or \
		(mal_a != 0 and mal_b != 0 and a * 1.0 / mal_a >= thresholds.api_chains_identical_num_chains and b * 1.0 / mal_b >= thresholds.api_chains_identical_len_chains):
			flag_similar = True
	else:
		common_chains = []
		if api_chains.chains_unique(api_chains_app, api_chains_sample_list, common_chains):
			flag_similar = True
	if flag_similar:
		print 'Common API chains with', sample
		is_malicious = True
		for i in range(0, len(common_chains)):
			for j in range(0, len(common_chains[i].chain)):
				if common_chains[i].chain[j] in interesting_api.interesting_api:
					common_chains[i].chain[j] = '*******************************************' + common_chains[i].chain[j]

		for i in range(0, len(common_chains)):
			print 'Root1:', common_chains[i].root, 'len:', len(api_chains_app_dict[common_chains[i].root])
			print api_chains_app_dict[common_chains[i].root]
			print 'Root2:', common_chains[i].root2, 'len:', len(api_chains_sample_dict[common_chains[i].root2])
			print api_chains_sample_dict[common_chains[i].root2]
			print 'Components: ', common_chains[i].components
			print 'Common chain length: ', len(common_chains[i].chain)
			for j in range(0, len(common_chains[i].chain)):
				print common_chains[i].chain[j]
			print '-------------------------------------------------------------------'
		print '___________________________________________________________________'
time_compare = time.time() - time_s

print 'Time to decompile:', time_decompile
print 'Time to compare perms:', time_perms
print 'Time to compare api:', time_api
print 'Time to build chain model', time_getting_chains
print 'Time to compare chains:', time_compare
print 'Time spent in lcs:', api_chains.time_spent_in_lcs
print 'Time on finding entry points:', api_chains.time_entry_points

if is_malicious:
	print 'Identified as malware'
