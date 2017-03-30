#!/usr/bin/python
import sys
import copy

sys.path.append('../entry_points_discovery')
import entry_points_discovery_module

sys.path.append('../')
import known_libs
import interesting_api
import thresholds

sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from sets import Set

class ApiChain:
	def __init__(self, root = '', chain = [], root2 = '', components = 0):
		self.chain = chain
		self.root = root
		self.root2 = root2
		self.components = components

threshold_common_length = thresholds.api_chains_common_length #ratio
threshold_suspicious_length = thresholds.api_chains_suspicious_length
threshold_length = thresholds.api_chains_length
minimum_length = thresholds.api_chains_minimum_length

api_json = '../api.json'
#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

def isSuspiciousCall(api_call):
	if api_call in interesting_api.interesting_api:
		return True
	else:
		return False

def lcs_min_comp_get_chain(api_chain1, api_chain2, lcs):
	#returns lcs length, number of components and presence of suspicious calls
	f = [[0 for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]
	info = [[Set() for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]

	for i in range(0, len(api_chain1) + 1):
		for j in range(0, len(api_chain2) + 1):
			if (i == 0 or j == 0):
				f[i][j] = 0
			else:
				if api_chain1[i - 1] == api_chain2[j - 1]:
					f[i][j] = f[i-1][j-1] + 1
					if len(info[i-1][j-1]) == 0:
						info[i][j].add((i-1, isSuspiciousCall(api_chain1[i - 1]), 1, 0, 0, 0))
					else:
						comp_cur = -1
						susp_cur = False
						prev_l = -1
						for lp, suspp, compp, previ, prevj, prevl in info[i-1][j-1]:
							compt = compp if lp == i-2 else compp + 1
							if comp_cur == -1 or compt < comp_cur:
								comp_cur = compt
								susp_cur = suspp
								prev_l = lp
							if compt == comp_cur and suspp:
								susp_cur = suspp
								prev_l = lp
						susp_cur = susp_cur or isSuspiciousCall(api_chain1[i - 1])
						info[i][j].add((i-1, susp_cur, comp_cur, i-1, j-1, prev_l))
				else:
					f[i][j] = max(f[i-1][j], f[i][j-1])
					if (f[i-1][j] >= f[i][j-1]):
						info[i][j] = info[i][j].union(info[i-1][j])
					if (f[i-1][j] <= f[i][j-1]):
						info[i][j] = info[i][j].union(info[i][j-1])
					bestl = -1
					bestsusp = False
					bestcomp = -1
					bestprevi = -1
					bestprevj = -1
					bestprevl = -1
					rightmostl = -1
					rightmostsusp = False
					rightmostcomp = -1
					rightmostprevi = -1
					rightmostprevj = -1
					rightmostprevl = -1
					for lp, suspp, compp, previ, prevj, prevl in info[i][j]:
						if lp == i-1:
							rightmostl = lp
							rightmostsusp = suspp
							rightmostcomp = compp
							rightmostprevi = previ
							rightmostprevj = prevj
							rightmostprevl = prevl
							continue
						if bestcomp == -1 or compp < bestcomp:
							bestcomp = compp
							bestsusp = suspp
							bestl = lp
							bestprevi = previ
							bestprevj = prevj
							bestprevl = prevl
						if compp == bestcomp and suspp:
							bestsusp = suspp
							bestl = lp
							bestprevi = previ
							bestprevj = prevj
							bestprevl = prevl
					info[i][j] = Set()
					if rightmostl != -1 and (rightmostcomp < bestcomp + 2 or bestcomp == -1):
						info[i][j].add((rightmostl, rightmostsusp, rightmostcomp, rightmostprevi, rightmostprevj, rightmostprevl))
					if bestl != -1 and (bestcomp < rightmostcomp or rightmostcomp == -1):
						info[i][j].add((bestl, bestsusp, bestcomp, bestprevi, bestprevj, bestprevl))

	bestcomp = -1
	bestsusp = False
	bestl = -1
	for lp, suspp, compp, previ, prevj, prevl in info[len(api_chain1)][len(api_chain2)]:
		if bestcomp == -1 or compp < bestcomp:
			bestcomp = compp
			bestsusp = suspp
			bestl = lp
		if compp == bestcomp and suspp:
			bestsusp = suspp
			bestl = lp
	i = len(api_chain1)
	j = len(api_chain2)
	l = bestl
	while (i != 0 and j != 0):
		lcs.insert(0, api_chain1[l])
		for lp, suspp, compp, previ, prevj, prevl in info[i][j]:
			if lp == l:
				i = previ
				j = prevj
				l = prevl
				break
	return (f[len(api_chain1)][len(api_chain2)], bestcomp, bestsusp)

def lcs_min_comp_v2(api_chain1, api_chain2):
	#returns lcs length, number of components and presence of suspicious calls
	f = [[0 for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]
	info = [[Set() for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]

	for i in range(0, len(api_chain1) + 1):
		for j in range(0, len(api_chain2) + 1):
			if (i == 0 or j == 0):
				f[i][j] = 0
			else:
				if api_chain1[i - 1] == api_chain2[j - 1]:
					f[i][j] = f[i-1][j-1] + 1
					if len(info[i-1][j-1]) == 0:
						info[i][j].add((i-1, isSuspiciousCall(api_chain1[i - 1]), 1))
					else:
						comp_cur = -1
						susp_cur = False
						for lp, suspp, compp in info[i-1][j-1]:
							compt = compp if lp == i-2 else compp + 1
							if comp_cur == -1 or compt < comp_cur:
								comp_cur = compt
								susp_cur = suspp
							if compt == comp_cur and suspp:
								susp_cur = suspp
						susp_cur = susp_cur or isSuspiciousCall(api_chain1[i - 1])
						info[i][j].add((i-1, susp_cur, comp_cur))
				else:
					f[i][j] = max(f[i-1][j], f[i][j-1])
					if (f[i-1][j] >= f[i][j-1]):
						info[i][j] = info[i][j].union(info[i-1][j])
					if (f[i-1][j] <= f[i][j-1]):
						info[i][j] = info[i][j].union(info[i][j-1])
					bestl = -1
					bestsusp = False
					bestcomp = -1
					rightmostl = -1
					rightmostsusp = False
					rightmostcomp = -1
					for lp, suspp, compp in info[i][j]:
						if lp == i-1:
							rightmostl = lp
							rightmostsusp = suspp
							rightmostcomp = compp
							continue
						if bestcomp == -1 or compp < bestcomp:
							bestcomp = compp
							bestsusp = suspp
							bestl = lp
						if compp == bestcomp and suspp:
							bestsusp = suspp
							bestl = lp
					info[i][j] = Set()
					if rightmostl != -1 and (rightmostcomp < bestcomp + 2 or bestcomp == -1):
						info[i][j].add((rightmostl, rightmostsusp, rightmostcomp))
					if bestl != -1 and (bestcomp < rightmostcomp or rightmostcomp == -1):
						info[i][j].add((bestl, bestsusp, bestcomp))

	bestcomp = -1
	bestsusp = False
	for lp, suspp, compp in info[len(api_chain1)][len(api_chain2)]:
		if bestcomp == -1 or compp < bestcomp:
			bestcomp = compp
			bestsusp = suspp
		if compp == bestcomp and suspp:
			bestsusp = suspp
	return (f[len(api_chain1)][len(api_chain2)], bestcomp, bestsusp)

def longestCommonSubsequence(api_chain1, api_chain2):
	if (len(api_chain1) == 0 or len(api_chain2) == 0):
		return 0

	f = [[0 for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]
	prev = [[(0,0) for x in range(len(api_chain2) + 1)] for x in range(len(api_chain1) + 1)]
	for i in range(0, len(api_chain1) + 1):
		for j in range(0, len(api_chain2) + 1):
			if (i == 0 or j == 0):
				f[i][j] = 0
			elif api_chain1[i - 1] == api_chain2[j - 1]:
				f[i][j] = f[i-1][j-1] + 1
				prev[i][j] = (i-1, j-1)
			else:
				if (f[i-1][j] > f[i][j-1]):
					f[i][j] = f[i-1][j]
					prev[i][j] = (i-1, j)
				else:
					f[i][j] = f[i][j-1]
					prev[i][j] = (i, j-1)

	return f[len(api_chain1) ][len(api_chain2)]


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

def printApiChain(api_chain):
	print api_chain.root, ":", api_chain.chain

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

def get_api_chains(andr_a, andr_d):
	entry_points1 = []
	invokes1 = {}
	entry_points_discovery_module.find_entry_points(andr_a, andr_d, framework_api, entry_points1, invokes1)
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

def chains_unique(api_chains1, api_chains2, common_chains = None):
	if len(api_chains1) != len(api_chains2):
		return False
	api_chains1 = sorted(api_chains1, key = lambda api_chain: len(api_chain.chain), reverse = True)
	common_chains_count = 0
	mark_chains = [False for x in range(len(api_chains2))]
	for api_chain11 in api_chains1:
		api_chain1 = api_chain11.chain
		for i in range(len(api_chains2)):
			if mark_chains[i]:
				continue
			api_chain22 = api_chains2[i]
			api_chain2 = api_chains2[i].chain
			lcs_length = longestCommonSubsequence(api_chain1, api_chain2)

			if (lcs_length == len(api_chain1) and lcs_length == len(api_chain2)):
				common_chains_count += 1
				mark_chains[i] = True
			if common_chains != None:
				common_chains.append(ApiChain(api_chain11.root, api_chain1, api_chain22.root, 1))
	if common_chains_count == len(api_chains1):
		return True
	else:
		return False

def compare_api_chains(api_chains1, api_chains2, common_chains = None):
	common_dangerous_subsequences = 0 #long and dangerous do not intersect, in case of both it's considered dangerous
	common_long_subsequences = 0
	mark_chains = [False for x in range(len(api_chains2))]
	total_common_chains = 0
	total_common_length = 0

	api_chains1 = sorted(api_chains1, key = lambda api_chain: len(api_chain.chain), reverse = True)
	for api_chain11 in api_chains1:
		api_chain1 = api_chain11.chain
		longest_match_ind = 0
		longest_match_length = -1
		for i in range(len(api_chains2)):
			if mark_chains[i]:
				continue
			api_chain22 = api_chains2[i]
			api_chain2 = api_chains2[i].chain
			lcs_length = longestCommonSubsequence(api_chain1, api_chain2)

			if (lcs_length >= minimum_length and len(api_chain2) > 0 and \
				lcs_length * 1.0 / len(api_chain2) >= threshold_common_length):
				if lcs_length > longest_match_length:
					longest_match_ind = i
					longest_match_length = lcs_length

		if longest_match_length != -1:
			api_chain22 = api_chains2[longest_match_ind]
			api_chain2 = api_chain22.chain
			lcs = []
			chain_components_a = [0]
			chain_components = 0
			suspFlag = False
			lcs_length = 0
			if common_chains != None:
				lcs_length, chain_components, suspFlag = lcs_min_comp_get_chain(api_chain1, api_chain2, lcs)
			else:
				lcs_length, chain_components, suspFlag = lcs_min_comp_v2(api_chain1, api_chain2)
			flag_long = False
			flag_dangerous = False
			if lcs_length >= threshold_length and lcs_length >= 0.6 * len(api_chain2):
				common_long_subsequences += 1
				flag_long = True
			if suspFlag and lcs_length >= threshold_suspicious_length and (chain_components < lcs_length / 3 + 1):
				common_dangerous_subsequences += 1
				flag_dangerous = True
			if (chain_components < lcs_length / 3 + 1 or flag_long or flag_dangerous):
				total_common_chains += 1
				total_common_length += longest_match_length
				mark_chains[longest_match_ind] = True
				if common_chains != None:
					common_chains.append(ApiChain(api_chain11.root, lcs, api_chain22.root, chain_components))

	return total_common_chains, total_common_length, common_long_subsequences, common_dangerous_subsequences
