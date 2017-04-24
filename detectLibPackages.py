#!/usr/bin/python
import sys
import subprocess
import json
import known_libs
import os
import pydablooms
import md5

bbf_file = 'libs.bbf'
TH_COMMON_PACKAGE = 0.5
TH_COMMON_CLASS = 0.8

def set_bloom_filter(bbf_file):
	global bloom
	bloom = pydablooms.load_dabloom(capacity=10000000, error_rate=.05, filepath=bbf_file)

def transform_lib_name(name):
	return 'L' + name.replace('.', '/') 

def get_lib_classes(andr_d):
	global bloom
	lib_classes = []
	for cl in andr_d.get_classes():
		common_methods = 0
		if len(cl.get_methods()) == 0:
			continue
		for meth in cl.get_methods():
			op_array = []
			for ins in meth.get_instructions():
				opcode = ins.get_op_value()
				while True:
					op_array.append(opcode % 256)
					opcode /= 256
					if opcode == 0:
						break
			meth_str = ''.join(chr(x) for x in op_array)
			if bloom.check(md5.new(meth_str).hexdigest()):
				common_methods += 1
		if common_methods * 1.0 / len(cl.get_methods()) >= TH_COMMON_CLASS:
			lib_classes.append(cl.get_name())
	return lib_classes

def get_all_classes(andr_d):
	cl_list = []
	for cl in andr_d.get_classes():
		cl_list.append(cl.get_name())
	return cl_list

def detect_lib_packages_v2(andr_d):
	all_classes = get_all_classes(andr_d)
	lib_classes = get_lib_classes(andr_d)

	all_classes_pack = {}
	for cl in all_classes:
		splitted_name = cl.split("/")
		pack_name = splitted_name[0]
		ind = 1
		while ind < len(splitted_name):
			if not pack_name in all_classes_pack:
				all_classes_pack[pack_name] = 0
			all_classes_pack[pack_name] += 1
			pack_name += '/' + splitted_name[ind]
			ind += 1

	lib_classes_pack = {}
	for cl in lib_classes:
		splitted_name = cl.split("/")
		pack_name = splitted_name[0]
		ind = 1
		while ind < len(splitted_name):
			if not pack_name in lib_classes_pack:
				lib_classes_pack[pack_name] = 0
			lib_classes_pack[pack_name] += 1
			pack_name += '/' + splitted_name[ind]
			ind += 1

	common_libs = []

	for key in lib_classes_pack:
		key_prev = ''
		key_copy = key
		while lib_classes_pack[key_copy] * 1.0 / all_classes_pack[key_copy] >= TH_COMMON_PACKAGE:
			key_prev = key_copy
			if key_copy.rfind('/') == -1:
				break
			key_copy = key_copy[:key_copy.rfind('/')]
		if key_prev != '':
			for lib in known_libs.known_libs:
				if transform_lib_name(lib) in key_prev:
					key_prev = transform_lib_name(lib)
					break
			if not key_prev in common_libs:
				common_libs.append(key_prev)
	return common_libs
