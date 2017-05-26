#!/usr/bin/python
import json
import os
import sys
sys.path.append("../api_chains")
import api_chains

sys.path.append("../")
import common_classes

#loading malicious API chain models
fv_directory = '../api_chain_models'

malw_api_chain_models = {}
map_api_num = {}
count_calls = 0
malw_api_chain_models_in_lists = {}

for line in os.listdir(fv_directory):
	hashname = line
	features = json.loads(open(fv_directory + '/' + hashname, 'r').read())
	malw_api_chain_models[hashname] = features


for model in malw_api_chain_models:
	malw_api_chain_models_in_lists[model] = []

	for api_chain_root in malw_api_chain_models[model]:
		model_api_num = []
		for api_call in malw_api_chain_models[model][api_chain_root]:
			if not api_call in map_api_num:
				map_api_num[api_call] = count_calls
				count_calls += 1
			######
			call_cl = api_call[:api_call.find(';') + 1]
			if not call_cl in common_classes.very_common_classes:
				model_api_num.append(map_api_num[api_call])
			######
		added_chain = api_chains.ApiChain(api_chain_root, malw_api_chain_models[model][api_chain_root])
		added_chain.set_num_chain(model_api_num)
		malw_api_chain_models_in_lists[model].append(added_chain)

f = open('map_api_num.json', 'w')
f.write(json.dumps(map_api_num))
f.close()
