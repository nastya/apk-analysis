#!/usr/bin/python
import sys
import api_model
import interesting_api
sys.path.append('../')
import thresholds

from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

count_unused_api = False

#Loading framework methods
api_json = '../api.json'
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

def get_all_used_api(andr_d):
	try:
		used_api = []
		method_list = andr_d.get_methods()
		for method in method_list:
			if method.get_code() == None:
				continue

			cur_method = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
			for ins in method.get_instructions():
				if "invoke" in ins.get_name():
					call_method = ""
					matchObj = re.match( r'.*, ([^,]*)', ins.get_output(), re.M|re.I)
					if (matchObj):
						call_method = matchObj.group(1)
						if call_method[:1] == '[':
							call_method = call_method[1:]
						if call_method != "":
							call_method_class = call_method.split('->')[0]
							call_method_name = call_method.split('->')[1].split('(')[0]
							if call_method_class in framework_api \
								and call_method_name in framework_api[call_method_class] and \
								not call_method_class + call_method_name in used_api:
								used_api.append(call_method_class + call_method_name)
		return used_api
	except:
		print ('Failed to count api')
		return None


def get_used_api(apk_name):
	used_api = get_all_used_api(apk_name)
	if used_api == None:
		return None
	features = {}
	for func in interesting_api.interesting_api_20:
		features[func] = 0
	for func in used_api:
		if func in interesting_api.interesting_api_20:
			features[func] = 1
	return features


#[WARNING] the order of arguments is significant!!!
def similarity_function(vector_a, vector_m):
	matched = match_vectors(vector_a, vector_m)
	if count_unused_api:
		return matched * 1.0 / len(interesting_api.interesting_api_20)
	else:
		used_api_amount_m = 0
		used_api_amount_a = 0
		for api in vector_m:
			if vector_m[api]:
				used_api_amount_m += 1
		#for api in vector_a:
			#if vector_a[api]:
				#used_api_amount_a += 1
		if  used_api_amount_m != 0: #or used_api_amount_a != 0 
			return matched * 1.0 / used_api_amount_m #max(used_api_amount_m, used_api_amount_a)
		else:
			return 0.0

def hashname_similarity(api_fv, hashname):
	if hashname in api_model.malw_api_vectors:
		return similarity_function(api_fv, api_model.malw_api_vectors[hashname])
	else:
		return None

def get_matched_api(api_fv, hashname):
	matched_api = []
	for api in interesting_api.interesting_api_20:
		if api_fv[api] and api_fv[api] == api_model.malw_api_vectors[hashname][api]:
			matched_api.append(api)
	return matched_api

def match_vectors(vector1, vector2):
	matched = 0
	for api in interesting_api.interesting_api_20:
		if (vector1[api] or count_unused_api) and vector1[api] == vector2[api]:
			matched += 1
	return matched

def get_all_similarities(api_fv):
	similarities = []
	for m_name in api_model.malw_api_vectors:
		similarities.append(similarity_function(api_fv, api_model.malw_api_vectors[m_name]))
	return similarities

def get_max_similarity(api_fv, hashnames = None):
	max_s = 0
	hashname_max_sim = None
	for m_name in (hashnames if hashnames != None else api_model.malw_api_vectors):
		if not m_name in api_model.malw_api_vectors:
			continue
		matched_s = similarity_function(api_fv, api_model.malw_api_vectors[m_name])
		if matched_s > max_s:
			max_s = matched_s
			hashname_max_sim = m_name
	return max_s, hashname_max_sim
            
def get_similar_api(api_fv, hashnames):
	#print ('Getting similar API vectors...')
	if api_fv == None:
		return []
	similar = []
	for hashname in hashnames:
		if not hashname in api_model.malw_api_vectors:
			continue
		if similarity_function(api_fv, api_model.malw_api_vectors[hashname]) > thresholds.api_sim_function:
			similar.append(hashname)
	return similar
