#!/usr/bin/python
import pydablooms
import sys
import md5
sys.path.append('..')
import known_libs

from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

bloom = pydablooms.Dablooms(capacity=10000000, error_rate=.05, filepath='libs.bbf')

def isLibraryClass(classname, libs = None):
	package_method = False
	if libs == None:
		for package in known_libs.known_libs:
			package_name = "L" + package + "/"
			package_name = package_name.replace(".", "/")
			if package_name in classname:
				package_method = True
				break
	else:
		for package in libs:
			if package in classname:
				package_method = True
				break
	return package_method


def process(package_name, libs = None):
	global bloom
	print 'Processing ', package_name
	a = APK(package_name)
	d = dvm.DalvikVMFormat( a.get_dex() )
	hexdigests = []
	for cl in d.get_classes():
		if not isLibraryClass(cl.get_name(), libs):
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
			if not md5.new(meth_str).hexdigest() in hexdigests:
				hexdigests.append(md5.new(meth_str).hexdigest())
	for digest in hexdigests:
		bloom.add(digest)

app_libs = json.loads(open("apps_covering_known_libs.json", 'r').read())
for app in app_libs:
	process(app, app_libs[app])

bloom.flush()
del bloom
