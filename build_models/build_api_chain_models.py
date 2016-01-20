#!/usr/bin/python
# coding=utf-8
import sys
import hashlib
import os
import json
sys.path.append('../api_chains')
import api_chains

sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
import androlyze as anz

save_directory = "../api_chain_models"
if not os.path.exists(save_directory):
    os.makedirs(save_directory)


analyzed_apps = 'malware_for_models.txt'

f_list = open(analyzed_apps, 'r')
total_apps = sum(1 for line in open(analyzed_apps))

count_apps = 0
for line in f_list:
	apk_name = line[:-1]
	count_apps += 1
	print 'Processing', apk_name, '(', count_apps, ' / ', total_apps, ')'
	apk_hash = hashlib.sha256(open(apk_name, 'r').read()).hexdigest()

	a = APK(apk_name)
	d = dvm.DalvikVMFormat( a.get_dex() )

	app_api_chains = api_chains.get_api_chains(a, d)
	if app_api_chains == None:
		continue
	features = {}
	for chain in app_api_chains:
		features[chain.root] = chain.chain

	f = open(save_directory + "/" + apk_hash, 'w')
	f.write(json.dumps(features))
	f.close()

f_list.close()
