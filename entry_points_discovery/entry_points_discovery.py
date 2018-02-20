#!/usr/bin/python
# coding=utf-8
import sys
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from collections import deque

#import androlyze as anz

import pydot
import json
import os

import entry_points_discovery_module

api_json = "../api.json"

if (len(sys.argv) > 1):
	TEST = sys.argv[1]
else:
	#TEST = '../samples/FakeBanker/7276e76298c50d2ee78271cf5114a176'
	print 'Usage:'
	print sys.argv[0], 'apkfile [draw]'
	print "\t draw option stores function call graph plots by entry points in the directory named as apk package name"
	sys.exit()

a = APK(TEST)
d = dvm.DalvikVMFormat( a.get_dex() )
#x = VMAnalysis(d)

#a, d, x = anz.AnalyzeAPK(TEST,decompiler='dex2jar')

#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

entry_points = []
invokes = {}
entry_points_discovery_module.find_entry_points(a, d, framework_api, entry_points, invokes)

print 'Entry points:', len(entry_points)
auxiliary_list = []
for method in entry_points:
	auxiliary_list.append(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
	#print method.get_class_name() + "->" + method.get_name() + method.get_descriptor(), method_class_map[method].get_superclassname()
	
for method in sorted(auxiliary_list):
	print method

if len(sys.argv) > 2 and sys.argv[2] == 'draw':
	directory = a.get_package()
	if not os.path.exists(directory):
		os.makedirs(directory)
	for method in entry_points:
		graph = pydot.Dot(graph_type='digraph')
		mark = {}
		node = pydot.Node(method.get_class_name()+ "->" + method.get_name() + method.get_descriptor(),
			style="filled", fillcolor="white", shape = "rectangle")
		graph.add_node(node)
		mark[method.get_class_name()+ "->" + method.get_name() + method.get_descriptor()] = node
		queue = deque([])
		queue.append(method.get_class_name()+ "->" + method.get_name() + method.get_descriptor())
		while len(queue) > 0:
			cur_method = queue[0]
			queue.popleft()
			if not cur_method in invokes:
				continue
			for child in invokes[cur_method]:
				if not child in mark:
					node = pydot.Node(child, style="filled", fillcolor="white", shape = "rectangle")
					graph.add_node(node)
					mark[child] = node
					queue.append(child)
					graph.add_edge(pydot.Edge(mark[cur_method], mark[child]))
		name = method.get_class_name()[1:-1]+ "." + method.get_name()
		name = name.replace("/", ".") 
		#graph.write_dot(directory + "/" + name + '.dot')
		graph.write_svg(directory + "/" + name + '.svg')
