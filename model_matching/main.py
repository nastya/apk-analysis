#!/usr/bin/python
import sys
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

from optparse import OptionParser

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
import uuid

def find(pattern, path):
	result = []
	for root, dirs, files in os.walk(path):
		for name in files:
			if fnmatch.fnmatch(name, pattern):
				result.append(os.path.join(root, name))
	return result

usage = "Usage: %prog [options] apkfile"
parser = OptionParser(usage)
parser.add_option("-o", "--output", dest="out_dir",
				  help="specifies where to store output such as graphs and chains")
parser.add_option("-b", "--bloom", dest="bloom",
				  help="enables filtering library packages using bloom filter with hashes, by default this filtering is done via string matching", metavar="FILE")

(options, args) = parser.parse_args()
if len(args) < 1:
	print 'No apkfile specified to analyze'
	parser.print_help()
	sys.exit()
package_name = args[0]
if options.bloom:
	api_chains.bloom_f = True
	detectLibPackages.set_bloom_filter(options.bloom)
out_dir = options.out_dir or 'graphs_dir'
if not os.path.exists(out_dir):
	os.makedirs(out_dir)

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

# Generating cfg using pydot
import pydot
invokes, entry_points, mark = api_chains.get_graph_and_entry_points(andr_a, andr_d)
graph = pydot.Dot(graph_type='digraph', rankdir='LR')
added_nodes = {}
for key in entry_points:
	if not key in mark:
		continue
	node_key = pydot.Node(str(key), style="filled", fillcolor="green")
	graph.add_node(node_key)
	added_nodes[key] = node_key

for key in mark.keys():
	if not key in added_nodes:
		node_key = pydot.Node(str(key))
		graph.add_node(node_key)
		added_nodes[key] = node_key
	else:
		node_key = added_nodes[key]

	if not key in invokes:
		continue

	for to_key in invokes[key]:
		if not to_key in added_nodes:
			node_to_key = pydot.Node(str(to_key))
			graph.add_node(node_to_key)
			added_nodes[to_key] = node_to_key
		else:
			node_to_key = added_nodes[to_key]
		graph.add_edge(pydot.Edge(node_key, node_to_key))
graph.write_png(out_dir + '/cfg.png')

def gen_chain_png(chain_analyzed, chain_malware, common_chain, filename):
	graph = pydot.Dot(graph_type='digraph')
	prev_node = None
	c_chain = common_chain.chain[:]
	for item in chain_analyzed:
		uid = uuid.uuid4()
		if item in c_chain:
			node = pydot.Node(str(uid), label=str(item), style="filled", fillcolor="grey", color='black')
			c_chain.remove(item)
		else:
			node = pydot.Node(str(uid), label=str(item), color='black')
		graph.add_node(node)
		if prev_node:
			graph.add_edge(pydot.Edge(prev_node, node))
		prev_node = node
	prev_node = None
	c_chain = common_chain.chain[:]
	for item in chain_malware:
		uid = uuid.uuid4()
		if item in c_chain:
			node = pydot.Node(str(uid), label=str(item), style="filled", fillcolor="grey", color='red')
			c_chain.remove(item)
		else:
			node = pydot.Node(str(uid), label=str(item), color='red')
		graph.add_node(node)
		if prev_node:
			graph.add_edge(pydot.Edge(prev_node, node))
		prev_node = node
	graph.write_png(filename)

api_chains_app_dict = {}
for api_chain in api_chains_app:
	api_chains_app_dict[api_chain.root] = api_chain.chain

is_malicious = False

time_s = time.time()
matched_sample = ""  # matching malware sample for which we build png chains
all_matched = []
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
			if matched_sample == "":
				matched_sample = sample
	else:
		common_chains = []
		if api_chains.chains_unique(api_chains_app, api_chains_sample_list, common_chains):
			flag_similar = True
			if matched_sample == "":
				matched_sample = sample

	if flag_similar:
		all_matched.append(sample)
		print 'Common API chains with', sample
		is_malicious = True
		for i in range(0, len(common_chains)):
			for j in range(0, len(common_chains[i].chain)):
				if common_chains[i].chain[j] in interesting_api.interesting_api:
					common_chains[i].chain[j] = '*******************************************' + common_chains[i].chain[j]

		for i in range(0, len(common_chains)):
			if sample == matched_sample:
				gen_chain_png(api_chains_app_dict[common_chains[i].root], api_chains_sample_dict[common_chains[i].root2],
						common_chains[i], out_dir + '/chains_' + str(i) + '.png')
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

f = open(out_dir + '/verdict.txt', 'w')
if is_malicious:
	f.write('malware')
	print 'Identified as malware'
else:
	f.write('benign')
f.close()
if all_matched != []:
	f = open(out_dir + '/similar_samples.txt', 'w')
	f.write('\n'.join(all_matched))
	f.close()
	f = open(out_dir + '/malware_sample_to_match.txt', 'w')
	f.write(matched_sample)
	f.close()
	f = open(out_dir + '/matched_permissions.txt', 'w')
	f.write('\n'.join(permission_matching.get_matched(perms, matched_sample)))
	f.close()
	f = open(out_dir + '/matched_api.txt', 'w')
	f.write('\n'.join(api_matching.get_matched_api(api, matched_sample)))
	f.close()
