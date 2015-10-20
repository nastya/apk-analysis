#!/usr/bin/python
import json
import os

#loading malicious permission models
fv_directory = '../perms_fv'

malw_perm_vectors = {}

for line in os.listdir(fv_directory):
	hashname = line
	features = json.loads(open(fv_directory + '/' + hashname, 'r').read())
	malw_perm_vectors[hashname] = features
