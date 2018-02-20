#!/usr/bin/python
import sys
import permission_model
sys.path.append('../')
import system_perms
import thresholds

from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *


def get_perm_vector(andr_a):
	#print ('Getting permissions vector...')
	perms = andr_a.get_permissions()
	perms_set = set(perms)

	perms_fv = {}
	for perm in system_perms.permissions:
		perms_fv[perm] = 0
	for perm in perms_set:
		if perm in perms_fv:
			perms_fv[perm] = 1
	return perms_fv

def get_matched(perms, hashname):
	matched = []
	for perm in perms:
			if perms[perm] == 1 and perms[perm] ==  permission_model.malw_perm_vectors[hashname][perm]:
				matched.append(perm)
	return matched
    

def get_similar(perms):
	#print ('Getting similar permission vectors...')
	if perms == None:
		return []
	similar_hashes = []
	for hashname in  permission_model.malw_perm_vectors:
		score = 0
		a_count = 0
		b_count = 0
		for perm in perms:
			if perms[perm] == 1 and perms[perm] ==  permission_model.malw_perm_vectors[hashname][perm]:
				score += system_perms.perms_weight[perm]
			if perms[perm] == 1 and perms[perm] != permission_model.malw_perm_vectors[hashname][perm]:
				score += thresholds.perm_coef_extra
			if perms[perm] == 1:
				a_count += 1
			if permission_model.malw_perm_vectors[hashname][perm] == 1:
				b_count += 1
		if (b_count != 0):
			similarity = score * 0.5 / (b_count)
		else:
			similarity = 1 
		if similarity >= thresholds.perm_sim_function:
			similar_hashes.append(hashname)
	return similar_hashes

