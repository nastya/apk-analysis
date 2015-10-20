#!/usr/bin/python
import json
import os

#loading malicious API models
fv_directory = '../api_fv'

malw_api_vectors = {}

for line in os.listdir(fv_directory):
	hashname = line
	features = json.loads(open(fv_directory + '/' + hashname, 'r').read())
	malw_api_vectors[hashname] = features
