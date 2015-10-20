#!/usr/bin/python
known_libs = [
	# Big companies and SDKs
	#'android',
	#'com.android',
	'android.support',
	'com.google',
	'com.facebook',
	'com.adobe',
	'org.apache',
	'com.amazon',
	'com.amazonaws',
	'com.dropbox',
	'com.paypal',
	'twitter4j',
	'mono',
	'gnu',

	# Other stuff
	'org.kobjects',
	'com.squareup',
	'com.appbrain',
	'org.kxml2',
	'org.slf4j',
	'org.jsoup',
	'org.ksoap2',
	'org.xmlpull',
	'com.nineoldandroids',
	'com.actionbarsherlock',
	'com.viewpagerindicator',
	'com.nostra13.universalimageloader',
	'com.appyet', # App creator: appyet.com
	'com.fasterxml.jackson', # A suite of data-processing tools for Java: github.com/FasterXML/jackson
	'org.anddev.andengine', 'org.andengine', # Free Android 2D OpenGL Game Engine: andengine.org
	'uk.co.senab.actionbarpulltorefresh', # A pull-to-refresh lib: github.com/chrisbanes/ActionBar-PullToRefresh
	'fr.castorflex.android.smoothprogressbar', # A progressbar lib: github.com/castorflex/SmoothProgressBar
	'org.codehaus', # org.codehaus.jackson, org.codehaus.mojo, etc.
	'org.acra', # Application crash reports lib
	'com.appmk', # SDK for building simple android apps without programming (books, magazines)
	'com.j256.ormlite', # ORM library
	'nl.siegmann.epublib', #java library for managing epub files
	'pl.polidea', #Android library which simplifies displaying, caching and managing a lifecycle of images fetched from the web
	'uk.co.senab', #library for pull-to-refresh interaction
	'com.onbarcode', #library for QRcode
	'com.googlecode.apdfviewer', #library for viewing pdf
	'com.badlogic.gdx', #Java game development framework
	'com.crashlytics', #integrations for popular third-party services
	'com.mobeta.android.dslv', #extension of the Android ListView that enables drag-and-drop reordering of list items
	'com.andromo', #simplifies app creation
	'oauth.signpost', #for signing http messages
	'com.loopj.android.http', #An asynchronous callback-based Http client for Android built on top of Apache's HttpClient libraries.
	'com.handmark.pulltorefresh.library', #aims to provide a reusable Pull to Refresh widget for Android
	'com.bugsense.trace', #Remotely log unhandled exceptions in Android applications
	'org.cocos2dx.lib', #project demonstrating a method of setting a global opacity on a particle system
	'com.esotericsoftware', #for creating games
	'javax.inject', #package specifies a means for obtaining objects in such a way as to maximize reusability, testability and maintainability compared to traditional approaches 
	'com.parse', #framework for creating apps
	'org.joda.time', #date and time library for Java
	'com.androidquery', #library for doing asynchronous tasks and manipulating UI elements in Android
	'crittercism.android', #Monitor, prioritize, troubleshoot, and trend your mobile app performance
	'biz.source_code.base64Coder', #A Base64 encoder/decoder in Java
	'v2.com.playhaven', #mobile game LTV-maximization platform
	'xmlwise', #Xmlwise aims to make reading and writing of simple xml-files painless
	'org.springframework', #Spring Framework provides a comprehensive programming and configuration model for modern Java-based enterprise applications
	'org.scribe', #The best OAuth library out there
	'org.opencv', #OpenCV was designed for computational efficiency and with a strong focus on real-time applications
	'org.dom4j',
	'net.lingala.zip4j', #An open source java library to handle zip files
	'jp.basicinc.gamefeat', #Looks like a framework for games, Chineese
	'gnu.kawa', #Kawa is a general-purpose programming language that runs on the Java platform
	'com.sun.mail', #JavaMail API
	'com.playhaven', #Mobile Gaming Monetization Platform
	'com.commonsware.cwac', #open source libraries to help solve various tactical problems with Android development
	'com.comscore', #Analytics
	'com.koushikdutta', # low level network protocol library
	'com.mapbar', #Maps
	'greendroid', #GreenDroid is a development library for the Android platform. It is intended to make UI developments easier and consistent through your applications.
	'javax', #Java API
	'org.intellij', # Intellij

	# Ad networks
	'com.millennialmedia',
	'com.inmobi',
	'com.revmob',
	'com.mopub',
	'com.admob',
	'com.flurry',
	'com.adsdk',
	'com.Leadbolt',
	'com.adwhirl', # Displays ads from different ad networks
	'com.airpush',
	'com.chartboost', #In fact, SDK for displaying appropriate network
	'com.pollfish',
	'com.getjar', #offerwall for Android,
	'com.jb.gosms',
	'com.sponsorpay',
	'net.nend.android',
	'com.mobclix.android',
	'com.tapjoy',
	'com.adfonic.android',
	'com.applovin',
	'com.adcenix',
	'com.ad_stir',
	#Ad networks found in drebin database (still looking good)
	'com.madhouse.android.ads',
	'com.waps',
	'net.youmi.android',
	'com.vpon.adon',
	'cn.domob.android.ads',
	'com.wooboo.adlib_android',
	'com.wiyun.ad',
	
	#libs used in drebin (various) common in clusters
	'com.apperhand', #bad
	'com.localytics',
	'com.adwo.adsdk',
	'ad.imadpush', #bad
	'org.simpleframework.xml',
	'com.thoughtworks.xstream',
	'kawa',
	'com.pontiflex',
	'com.scoreloop',
	'com.mobclick',

	#Some unknown libs
	'com.jeremyfeinstein.slidingmenu.lib',
	'com.slidingmenu.lib',
	'it.sephiroth.android.library',
	'com.gtp.nextlauncher.library',
	'jp.co.nobot.libAdMaker',
	'ch.boye.httpclientandroidlib',
	'magmamobile.lib',
	'com.magmamobile'
]
 
