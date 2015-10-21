#!/usr/bin/python
import json
import os

#loading malicious API chain models
fv_directory = '../api_chain_models'

malw_api_chain_models = {}

for line in os.listdir(fv_directory):
	hashname = line
	features = json.loads(open(fv_directory + '/' + hashname, 'r').read())
	malw_api_chain_models[hashname] = features
