#!/usr/bin/python
import sys
import operator
import json
sys.path.append('../')
import system_perms
import hashlib
import os

sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

fv_directory = '../perms_fv'
if not os.path.exists(fv_directory):
    os.makedirs(fv_directory)
analyzed_apps = 'malware_for_models.txt'

f = open(analyzed_apps, 'r')
total_apps = sum(1 for line in open(analyzed_apps))

count_apps = 0
for line in f:
	package_name = line[:-1]
	count_apps += 1
	print 'Processing', package_name, '(', count_apps, ' / ', total_apps, ')'
	apk_hash = hashlib.sha256(open(package_name, 'r').read()).hexdigest()
	if os.path.isfile(fv_directory + '/' + apk_hash):
		continue

	#getting permissions
	try:
		a = APK(package_name)
		perms = a.get_permissions()
		perms_set = set(perms)
	except:
		print 'Failed to get manifest'
		continue

	#building feature vector
	perms_fv = {}
	for perm in system_perms.permissions:
		perms_fv[perm] = 0
	for perm in perms_set:
		if perm in perms_fv:
			perms_fv[perm] = 1
                
	#saving
	out_f = open(fv_directory + '/' + apk_hash, 'w')
	out_f.write(json.dumps(perms_fv, sort_keys=True, indent=4, separators=(',', ': ')))
	out_f.close()
        
        
f.close()

