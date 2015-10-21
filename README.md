# apk-analysis
  Scripts for analysing Android applications.
  
  Scripts implement static analysis of Android applications based on permissions, Android framework API and other libs API calls.
  
  Usage:
  
  1) Generate models of malicious Android applications, running all the scripts in build_models/ directory. A list of malicious apps for building models is specified in build_models/malware_for_models.txt
  
  2) To compare a suspicious app with generated models, run model_matching/main.py
  
  3) If you want to measure the accuracy of the provided analysis, run model_matching/main_set.py specifying malicious apps in model_matching/malware_for_analysis.txt and benign apps in model_matching/benign_for_analysis.txt
