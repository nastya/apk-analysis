#!/usr/bin/python
import permission_matching
import api_matching
import sys

if (len(sys.argv) > 1):
	package_name = sys.argv[1]
else:
	print 'Usage:'
	print sys.argv[0], 'apkfile'
	sys.exit()

perms = permission_matching.get_perm_vector(package_name)
similar_list = permission_matching.get_similar(perms)
if similar_list != []:
	print 'Similar malware by permissions:'
	for x in similar_list:
		print x
	print '___________________________________________________________________'

api = api_matching.get_used_api(package_name)
similar_api_list = api_matching.get_similar_api(api, similar_list)

if len(similar_api_list) != 0:
	print 'Similar malware by API:'
	for x in similar_api_list:
		print x
	print '___________________________________________________________________'
else:
	print 'No API-similarities with malware models'
