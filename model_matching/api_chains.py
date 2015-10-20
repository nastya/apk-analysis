#!/usr/bin/python
import sys
import copy

sys.path.append('../entry_points_discovery')
import entry_points_discovery_module

sys.path.append('../')
import known_libs
import interesting_api

sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
import androlyze as anz

import os, fnmatch
samples_dir = "../../drebin_samples"
def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result

class ApiChain:
	def __init__(self, root = '', chain = [], root2 = ''):
		self.chain = chain
		self.root = root
		self.root2 = root2

threshold_common_length = 0.85 #percentage
threshold_suspicious_length = 6
threshold_length = 20 #methods in API chain
threshold_total_common_chains = 7
threshold_total_common_length = 30
threshold_identical_num_chains = 0.95
threshold_identical_len_chains = 0.95
minimum_length = 3
limit = 50

api_json = '../api.json'
#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

def longestCommonSubsequence(api_chain1, api_chain2, lcs = None):
	if (len(api_chain1) == 0 or len(api_chain2) == 0):
		return 0
	f = [[0 for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]
	for i in range(0, len(api_chain1) + 1):
		for j in range(0, len(api_chain2) + 1):
			if (i == 0 or j == 0):
				f[i][j] = 0
			elif api_chain1[i - 1] == api_chain2[j - 1]:
				f[i][j] = f[i-1][j-1] + 1
			else:
				f[i][j] = max(f[i-1][j], f[i][j-1])
	if lcs == None:
		return f[len(api_chain1) ][len(api_chain2)]

	#getting the longestCommonSubsequence itself
	i = len(api_chain1)
	j = len(api_chain2)
	while i != 0 and j != 0:
		if i != 0 and j != 0 and f[i][j] == f[i-1][j-1] + 1:
			lcs.insert(0, api_chain1[i - 1])
			i = i - 1
			j = j - 1
		elif i != 0 and f[i][j] == f[i-1][j]:
			i = i - 1
		elif j != 0 and f[i][j] == f[i][j-1]:
			j = j - 1
		else:
			print 'Oops, I was wrong', i, j
	return len(lcs)

def simplifyAPIChain(api_chain):
	api_chain_simplified = []
	for invoke in api_chain:
		cl_name = invoke.split("->")[0]
		meth_name = invoke.split("->")[1].split("(")[0]
		api_chain_simplified.append(cl_name + meth_name)
	return api_chain_simplified

def isLibraryClass(classname):
	package_method = False
	for package in known_libs.known_libs:
		package_name = "L" + package + "/"
		package_name = package_name.replace(".", "/")
		if package_name in classname:
			package_method = True
			break
	return package_method

def isSuspiciousChain(api_chain):
	for api_call in api_chain:
		if api_call in interesting_api.interesting_api:
			return True
	return False

def dfs(root, invokes, mark, api_chain, consider_libs = False):
	if (not consider_libs and isLibraryClass(root.split("->")[0])):
		return

	if not root in mark or mark[root] == False:
		mark[root] = True
	else:
		return
	if (not root in invokes):
		return
	for invoke in invokes[root]:
		cl_name = invoke.split("->")[0]
		meth_name = invoke.split("->")[1].split("(")[0]
		if cl_name in framework_api and meth_name in framework_api[cl_name]:
			api_chain.append(invoke)
		if (not consider_libs and isLibraryClass(cl_name)):
			api_chain.append(invoke)
			continue
		dfs(invoke, invokes, mark, api_chain)

def get_api_chains(app):
	try:
		a = APK(app)
		d = dvm.DalvikVMFormat( a.get_dex() )
	except:
		return None

	entry_points1 = []
	invokes1 = {}
	entry_points_discovery_module.find_entry_points(a, d, framework_api, entry_points1, invokes1)
	mark1 = {}
	mark_before = {}
	api_chains1 = []
	for method in entry_points1:
		root = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
		api_chain = []
		mark_before = copy.deepcopy(mark1)
		dfs(root, invokes1, mark1, api_chain, True) #traversing library calls
		if (not isSuspiciousChain(simplifyAPIChain(api_chain))):
			api_chain = []
			mark1 = copy.deepcopy(mark_before)
			dfs(root, invokes1, mark1, api_chain) #ignoring library calls
		if (api_chain == []):
			continue
		#print root
		#print 'API chain: ', api_chain
		
		api_chains1.append(ApiChain(root, simplifyAPIChain(api_chain)))
	return api_chains1

def compare_api_chains(api_chains1, api_chains2, common_chains = None):
	common_dangerous_subsequences = 0 #long and dangerous do not intersect, in case of both it's considered dangerous
	common_long_subsequences = 0
	mark_chains = [False for x in range(len(api_chains2))]
	total_common_chains = 0
	total_common_length = 0

	for api_chain11 in api_chains1:
		api_chain1 = api_chain11.chain
		for i in range(len(api_chains2)):
			if mark_chains[i]:
				continue
			api_chain22 = api_chains2[i]
			api_chain2 = api_chains2[i].chain
			lcs = []
			lcs_length = longestCommonSubsequence(api_chain1, api_chain2, lcs)
			common_chain_added = False
			if (lcs_length >= minimum_length and len(api_chain2) > 0 and \
				lcs_length * 1.0 / len(api_chain2) >= threshold_common_length):
				total_common_chains += 1
				total_common_length += lcs_length
				if common_chains != None:
					common_chains.append(ApiChain(api_chain11.root, lcs, api_chain22.root))
					common_chain_added = True
				mark_chains[i] = True
			if isSuspiciousChain(lcs) and lcs_length >= threshold_suspicious_length:
				common_dangerous_subsequences += 1
				if common_chains != None and not common_chain_added:
					common_chains.append(ApiChain(api_chain11.root, lcs, api_chain22.root))
					common_chain_added = True
				mark_chains[i] = True
				break
			if lcs_length >= threshold_length and lcs_length >= 0.5 * len(api_chain2):
				common_long_subsequences += 1
				if common_chains != None and not common_chain_added:
					common_chains.append(ApiChain(api_chain11.root, lcs, api_chain22.root))
					common_chain_added = True
				mark_chains[i] = True
			if mark_chains[i]:
				break
	return total_common_chains, total_common_length, common_long_subsequences, common_dangerous_subsequences

def get_similar(app, app_list):
	api_chains_app = get_api_chains(app)
	if (api_chains_app == None):
		return []
	similar_apps = []

	for sample in app_list:
		found_fls = find(sample, samples_dir)
		sample_full_path = found_fls[0] if len(found_fls) > 0 else None
		if sample_full_path == None:
			continue
		api_chains_sample = get_api_chains(sample_full_path)
		if (api_chains_sample == None):
			continue
		mal_a = sum((1 if len(x.chain) >= minimum_length else 0) for x in api_chains_sample)
		mal_b = sum((len(x.chain) if len(x.chain) >= minimum_length else 0) for x in api_chains_sample)
		common_chains = []
		a,b,c,d = compare_api_chains(api_chains_app, api_chains_sample, common_chains)

		if (a >= threshold_total_common_chains and b >= threshold_total_common_length) or \
			(c >= 2) or (c >= 1 and d >= 1) or \
			(d >= 2 and b >= threshold_total_common_length) or \
			(mal_a != 0 and mal_b != 0 and a * 1.0 / mal_a >= threshold_identical_num_chains and b * 1.0 / mal_b >= threshold_identical_len_chains):
			similar_apps.append(sample)
	return similar_apps

