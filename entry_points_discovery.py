#!/usr/bin/python
# coding=utf-8
import sys
sys.path.append('../androguard')

from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from collections import deque

import androlyze as anz

import pydot
import json
import os

api_json = "api.json"
consider_layout = True

if (len(sys.argv) > 1):
	TEST = sys.argv[1]
else:
	#TEST = '../samples/FakeBanker/7276e76298c50d2ee78271cf5114a176'
	print 'Usage:'
	print sys.argv[0], 'apkfile [draw]'
	print "\t draw option stores function call graph plots by entry points in the directory named as apk package name"
	sys.exit()

#a = APK(TEST)
#d = dvm.DalvikVMFormat( a.get_dex() )
#x = VMAnalysis(d)

a, d, x = anz.AnalyzeAPK(TEST,decompiler='dex2jar')

#Auxiliary structures. Perhaps I did not found the corresponding interfaces in the Androguard tool.
string_method_map = {}
string_class_map = {}
method_class_map = {}

for cl in d.get_classes():
	string_class_map[cl.get_name()] = cl
	for method in cl.get_methods():
		method_class_map[method] = cl
		name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
		string_method_map[name] = method
		if method.get_name() == "<init>": #Init is separated to provide simple getting of constructors 
			if method.get_class_name() + "->" + method.get_name() in string_method_map:
				string_method_map[method.get_class_name() + "->" + method.get_name()].append(method)
			else:
				string_method_map[method.get_class_name() + "->" + method.get_name()] = [method]

#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

#Getting main application components classes and their methods

main_component_methods = []

for comp in a.get_activities() + a.get_services() + a.get_receivers() + a.get_providers():
	comp = comp.replace(".", "/");
	comp = "L" + comp + ";"
	if comp in string_class_map.keys():
		main_component_methods.extend(string_class_map[comp].get_methods())
	else:
		print(comp, " was not found in class map.")

methods = []
for method in d.get_methods():
	methods.append(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())

invokes = {}
isinvoked = {}
calls = []
for method in d.get_methods():
	g = x.get_method(method)

	if method.get_code() == None:
		continue

	idx = 0
	cur_method = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
	invokes[cur_method] = []
	for i in g.get_basic_blocks().get():
		for ins in i.get_instructions():
			if "invoke" in ins.get_name():
				call_method = ""
				matchObj = re.match( r'.*, ([^,]*)', ins.get_output(), re.M|re.I)
				if (matchObj):
					call_method = matchObj.group(1)
					if call_method[:1] == '[':
						call_method = call_method[1:]
				if call_method != "" and (not call_method in invokes[cur_method]):
					invokes[cur_method].append(call_method)
					if call_method in isinvoked and not cur_method in isinvoked[call_method]:
						isinvoked[call_method].append(cur_method)
					if not call_method in isinvoked:
						isinvoked[call_method] = [cur_method]
				if ( call_method != "" and ( not (call_method in calls) )):
					calls.append(call_method)
			idx += ins.get_length()

methods_framework_invoked = []

#Methods invoked by framework
#Actually, methods invoked by framework are only those reimplementing functions of base component classes
#In fact, these methods can be invoked by users (callbacks) or be unreachable code
#So we have probably redundant list of entry points invoked by framework and users (still not full)
if not consider_layout:
	for method in main_component_methods:
		name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
		if (not name in isinvoked.keys()) and (not "private" in method.get_access_flags_string()):
			methods_framework_invoked.append(method)
else:
	for method in main_component_methods:
		try:
			if method.get_name() in framework_api[method_class_map[method].get_superclassname()] or '<' in method.get_name():
				methods_framework_invoked.append(method)
		except:
			continue

	possible_entry_points_layout = []
	for file_name in a.get_files():
		matchObj = re.match( r'res/layout/.*', file_name, re.M|re.I)
		if matchObj:
			xml_file = AXMLPrinter(a.get_file(file_name)).get_xml()
			split_xml = xml_file.split("android:onClick=")
			for i in range(1, len(split_xml)):
				matchObj2 = re.match( r'"([^"]*)".*', split_xml[i], re.M|re.I)
				if matchObj2:
					possible_entry_points_layout.append(matchObj2.group(1))

	#print possible_entry_points_layout

	for ep in possible_entry_points_layout:
		for act in a.get_activities():
			act = act.replace(".", "/");
			act = "L" + act + ";"
			for method in string_class_map[act].get_methods():
				if method.get_name() == ep and not method in methods_framework_invoked:
					methods_framework_invoked.append(method)

#print 'Methods invoked by framework:', len(methods_framework_invoked)
#auxiliary_list = []
#for method in methods_framework_invoked:
	#name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
	#auxiliary_list.append(name)

#for method in sorted(auxiliary_list):
	#print method

graph = []
#Building initial graph. In fact, a list of reachable methods
queue = deque([])
mark = {}
for method in methods_framework_invoked:
	name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
	queue.append(name)
	mark[name] = True

def build_graph(queue, graph, mark):
	while len(queue) != 0:
		name = queue[0]
		graph.append(name.split("(")[0])
		queue.popleft()
		if not name in invokes.keys():
			continue
		for method in invokes[name]:
			if not method in mark:
				queue.append(method)
				mark[name] = True


build_graph(queue, graph, mark)

entry_points = methods_framework_invoked

for cl in d.get_classes():
	ok = False
	if cl.get_superclassname() in framework_api.keys():
		ok = True;
	interfaces = []
	if cl.get_interfaces() != None:
		interface_string = cl.get_interfaces()[1:-1]
		interfaces = interface_string.split(" ")
		for interface in interfaces:
			if interface in framework_api.keys():
				ok = True
	if not ok:
		continue
	for method in cl.get_methods():
		ok = False
		if cl.get_superclassname() in framework_api and method.get_name() in framework_api[cl.get_superclassname()]:
			ok = True;
		for interface in interfaces:
			if interface in framework_api and method.get_name() in framework_api[interface]:
				ok = True
		if not ok:
			continue
		#If we reached here method is overloading one of the framework methods
		name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
		if not name in mark and not name in isinvoked.keys() and cl.get_name() + "->" + "<init>" in graph:
				queue.append(name);
				mark[name] = True
				build_graph(queue, graph, mark)
				entry_points.append(method)

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

		