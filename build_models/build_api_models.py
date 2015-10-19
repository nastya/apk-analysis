#!/usr/bin/python
# coding=utf-8
import sys
import hashlib
import os
import json
sys.path.append('../')
import interesting_api

sys.path.append('../../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
import androlyze as anz

save_directory = "../api_fv"
if not os.path.exists(save_directory):
    os.makedirs(save_directory)

api_json = '../api.json'

#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()


def get_used_api(apk_name):
	try:
		#Androguard structures
		a = APK(apk_name)
		d = dvm.DalvikVMFormat( a.get_dex() )
		#x = VMAnalysis(d)
	except:
		print 'Failed to build Androguard structures'
		return None

	try:
		used_api = []
		method_list = d.get_methods()
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
		print 'Failed to count api'
		return None

analyzed_apps = 'malware_for_models.txt'

f_list = open(analyzed_apps, 'r')
total_apps = sum(1 for line in open(analyzed_apps))

count_apps = 0
for line in f_list:
	apk_name = line[:-1]
	count_apps += 1
	print 'Processing', apk_name, '(', count_apps, ' / ', total_apps, ')'
	apk_hash = hashlib.sha256(open(apk_name, 'r').read()).hexdigest()
	api = get_used_api(apk_name)
	features = {}
	for func in interesting_api.interesting_api_20:
		features[func] = 0
	if api != None:
		for func in api:
			if func in interesting_api.interesting_api_20:
				features[func] = 1
		f = open(save_directory + "/" + apk_hash, 'w')
		f.write(json.dumps(features))
		f.close()

f_list.close()
