#!/usr/bin/python
import sys
import api_chain_model
sys.path.append('../api_chains')
import api_chains

work_until_first_match = False

def get_similar(andr_a, andr_d, app_list):
	api_chains_app = api_chains.get_api_chains(andr_a, andr_d)
	if (api_chains_app == None):
		return []
	similar_apps = []

	for sample in app_list:
		if not sample in api_chain_model.malw_api_chain_models:
			continue
		api_chains_sample_dict = api_chain_model.malw_api_chain_models[sample]
		api_chains_sample_list = []
		for api_chain in api_chains_sample_dict:
			api_chains_sample_list.append(api_chains.ApiChain(api_chain, api_chains_sample_dict[api_chain]))
		mal_a = sum((1 if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample_list)
		mal_b = sum((len(x.chain) if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample_list)
		a,b,c,d = api_chains.compare_api_chains(api_chains_app, api_chains_sample_list)

		if (a >= api_chains.threshold_total_common_chains and b >= api_chains.threshold_total_common_length) or \
			(c >= 2) or (c >= 1 and d >= 1) or \
			(d >= 1 and b >= api_chains.threshold_total_common_length) or \
			(mal_a != 0 and mal_b != 0 and a * 1.0 / mal_a >= api_chains.threshold_identical_num_chains and b * 1.0 / mal_b >= api_chains.threshold_identical_len_chains):
			similar_apps.append(sample)
			if work_until_first_match:
				break
	return similar_apps

def get_similar_detailed(andr_a, andr_d, app_list):
	api_chains_app = api_chains.get_api_chains(andr_a, andr_d)
	if (api_chains_app == None):
		return []
	similar_apps = {}

	for sample in app_list:
		if not sample in api_chain_model.malw_api_chain_models:
			continue
		api_chains_sample_dict = api_chain_model.malw_api_chain_models[sample]
		api_chains_sample_list = []
		for api_chain in api_chains_sample_dict:
			api_chains_sample_list.append(api_chains.ApiChain(api_chain, api_chains_sample_dict[api_chain]))
		mal_a = sum((1 if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample_list)
		mal_b = sum((len(x.chain) if len(x.chain) >= api_chains.minimum_length else 0) for x in api_chains_sample_list)
		a,b,c,d = api_chains.compare_api_chains(api_chains_app, api_chains_sample_list)

		similar_apps[sample] = []
		if (a >= api_chains.threshold_total_common_chains and b >= api_chains.threshold_total_common_length):
			similar_apps[sample].append(1)
		if (c >= 2):
			similar_apps[sample].append(2)
		if (c >= 1 and d >= 1):
			similar_apps[sample].append(3)
		if (d >= 1 and b >= api_chains.threshold_total_common_length):
			similar_apps[sample].append(4)
		if (mal_a != 0 and mal_b != 0 and a * 1.0 / mal_a >= api_chains.threshold_identical_num_chains and b * 1.0 / mal_b >= api_chains.threshold_identical_len_chains):
			similar_apps[sample].append(5)
		if work_until_first_match and similar_apps[sample] != []:
				break
	return similar_apps
