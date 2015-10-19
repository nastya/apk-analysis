#!/usr/bin/python
interesting_api = [ #pscout
    "Landroid/app/ActivityManager;killBackgroundProcesses",
    "Landroid/location/LocationManager;getProvider",
    "Landroid/media/AudioManager;isWiredHeadsetOn",
    "Landroid/app/KeyguardManager$KeyguardLock;reenableKeyguard",
    "Landroid/speech/SpeechRecognizer;startListening",
    "Landroid/app/DownloadManager;enqueue",
    "Landroid/widget/VideoView;setVideoURI",
    "Landroid/media/Ringtone;setStreamType",
    "Landroid/location/LocationManager;setTestProviderLocation",
    "Landroid/nfc/NfcAdapter;enableForegroundDispatch",
    "Landroid/provider/Browser;getAllBookmarks",
    "Landroid/location/LocationManager;clearTestProviderStatus",
    "Ljava/net/URL;openConnection",
    "Landroid/app/WallpaperManager;setBitmap",
    "Landroid/bluetooth/BluetoothAdapter;getScanMode",
    "Landroid/bluetooth/BluetoothAdapter;isEnabled",
    "Landroid/media/AsyncPlayer;stop",
    "Landroid/telephony/gsm/SmsManager;sendMultipartTextMessage",
    "Landroid/widget/QuickContactBadge;assignContactFromPhone",
    "Landroid/net/wifi/WifiManager;enableNetwork",
    "Landroid/bluetooth/BluetoothDevice;getBondState",
    "Landroid/location/LocationManager;isProviderEnabled",
    "Landroid/content/Context;sendStickyBroadcast",
    "Landroid/bluetooth/BluetoothAdapter;disable",
    "Landroid/app/WallpaperManager;suggestDesiredDimensions",
    "Landroid/provider/Settings$System;putString",
    "Landroid/net/wifi/WifiManager;removeNetwork",
    "Ljava/net/ServerSocket;bind",
    "Landroid/telephony/TelephonyManager;getDeviceSoftwareVersion",
    "Landroid/content/ContentResolver;setMasterSyncAutomatically",
    "Landroid/net/wifi/WifiManager;saveConfiguration",
    "Landroid/telephony/TelephonyManager;getSubscriberId",
    "Landroid/media/MediaRecorder;setAudioSource",
    "Landroid/telephony/TelephonyManager;listen",
    "Ljava/net/URL;getContent",
    "Landroid/accounts/AccountManager;getAccountsByType",
    "Landroid/telephony/gsm/SmsManager;sendTextMessage",
    "Landroid/net/ConnectivityManager;getActiveNetworkInfo",
    "Landroid/media/AudioManager;setBluetoothScoOn",
    "Landroid/net/ConnectivityManager;stopUsingNetworkFeature",
    "Landroid/accounts/AccountManager;removeAccount",
    "Landroid/net/wifi/WifiManager;getWifiState",
    "Landroid/telephony/gsm/SmsManager;sendDataMessage",
    "Landroid/media/AudioManager;setSpeakerphoneOn",
    "Landroid/net/ConnectivityManager;requestRouteToHost",
    "Landroid/location/LocationManager;addNmeaListener",
    "Landroid/telephony/TelephonyManager;getVoiceMailNumber",
    "Landroid/bluetooth/BluetoothAdapter;isDiscovering",
    "Landroid/bluetooth/BluetoothAdapter;getState",
    "Landroid/app/NotificationManager;notify",
    "Landroid/provider/Browser;clearHistory",
    "Landroid/app/KeyguardManager$KeyguardLock;disableKeyguard",
    "Landroid/location/LocationManager;clearTestProviderEnabled",
    "Landroid/bluetooth/BluetoothAdapter;cancelDiscovery",
    "Landroid/media/AsyncPlayer;play",
    "Landroid/provider/Contacts$Settings;getSetting",
    "Landroid/net/wifi/WifiManager;setWifiEnabled",
    "Landroid/location/LocationManager;getProviders",
    "Landroid/os/PowerManager$WakeLock;release",
    "Landroid/location/LocationManager;getLastKnownLocation",
    "Landroid/widget/VideoView;pause",
    "Landroid/media/RingtoneManager;getRingtone",
    "Landroid/app/WallpaperManager;setStream",
    "Landroid/content/Context;setWallpaper",
    "Landroid/telephony/TelephonyManager;getLine1Number",
    "Landroid/net/ConnectivityManager;setNetworkPreference",
    "Landroid/net/wifi/WifiManager$WifiLock;acquire",
    "Landroid/provider/Browser;canClearHistory",
    "Landroid/telephony/TelephonyManager;getNeighboringCellInfo",
    "Landroid/app/ActivityManager;getRunningTasks",
    "Ljava/net/URLConnection;getInputStream",
    "Landroid/os/Vibrator;vibrate",
    "Landroid/media/MediaPlayer;setWakeMode",
    "Landroid/app/WallpaperManager;clear",
    "Landroid/media/MediaPlayer;start",
    "Landroid/app/ActivityManager;getRecentTasks",
    "Landroid/app/ActivityManager;restartPackage",
    "Landroid/content/Context;removeStickyBroadcast",
    "Landroid/provider/Contacts$People;addToMyContactsGroup",
    "Landroid/provider/Browser;clearSearches",
    "Landroid/media/MediaRecorder;setVideoSource",
    "Landroid/provider/Settings$System;getUriFor",
    "Landroid/media/AudioManager;setMode",
    "Landroid/telephony/TelephonyManager;getSimSerialNumber",
    "Landroid/net/wifi/WifiManager$WifiLock;release",
    "Landroid/speech/SpeechRecognizer;setRecognitionListener",
    "Landroid/net/wifi/WifiManager;pingSupplicant",
    "Landroid/net/wifi/WifiManager;getScanResults",
    "Landroid/hardware/Camera;open",
    "Landroid/provider/Browser;getAllVisitedUrls",
    "Landroid/location/LocationManager;setTestProviderEnabled",
    "Landroid/bluetooth/BluetoothAdapter;enable",
    "Landroid/net/wifi/WifiManager;disableNetwork",
    "Landroid/net/wifi/WifiManager;getDhcpInfo",
    "Landroid/telephony/SmsManager;sendMultipartTextMessage",
    "Ljava/net/URL;openStream",
    "Landroid/widget/VideoView;stopPlayback",
    "Landroid/media/AudioManager;isBluetoothA2dpOn",
    "Landroid/accounts/AccountManager;getAccounts",
    "Landroid/telephony/SmsManager;sendDataMessage",
    "Landroid/bluetooth/BluetoothAdapter;listenUsingRfcommWithServiceRecord",
    "Landroid/location/LocationManager;getBestProvider",
    "Landroid/os/Vibrator;cancel",
    "Landroid/net/wifi/WifiManager;isWifiEnabled",
    "Landroid/location/LocationManager;requestLocationUpdates",
    "Landroid/net/ConnectivityManager;getNetworkInfo",
    "Landroid/media/MediaPlayer;release",
    "Landroid/net/wifi/WifiManager;reconnect",
    "Landroid/provider/Contacts$People;createPersonInMyContactsGroup",
    "Landroid/media/MediaPlayer;reset",
    "Landroid/net/wifi/WifiManager;updateNetwork",
    "Landroid/net/wifi/WifiManager;disconnect",
    "Landroid/nfc/NfcAdapter;disableForegroundDispatch",
    "Landroid/media/RingtoneManager;setActualDefaultRingtoneUri",
    "Landroid/bluetooth/BluetoothAdapter;getAddress",
    "Landroid/provider/Contacts$People;queryGroups",
    "Landroid/widget/VideoView;start",
    "Landroid/media/MediaPlayer;pause",
    "Landroid/location/LocationManager;addProximityAlert",
    "Ljava/net/URLConnection;connect",
    "Landroid/widget/VideoView;resume",
    "Landroid/net/ConnectivityManager;startUsingNetworkFeature",
    "Landroid/location/LocationManager;sendExtraCommand",
    "Landroid/bluetooth/BluetoothAdapter;getBondedDevices",
    "Landroid/location/LocationManager;clearTestProviderLocation",
    "Landroid/media/Ringtone;play",
    "Landroid/telephony/TelephonyManager;getCellLocation",
    "Landroid/bluetooth/BluetoothDevice;getBluetoothClass",
    "Landroid/net/wifi/WifiManager;reassociate",
    "Landroid/accounts/AccountManager;clearPassword",
    "Landroid/bluetooth/BluetoothDevice;createRfcommSocketToServiceRecord",
    "Landroid/telephony/TelephonyManager;getDeviceId",
    "Landroid/net/ConnectivityManager;getAllNetworkInfo",
    "Landroid/provider/Settings$System;putInt",
    "Landroid/bluetooth/BluetoothAdapter;getName",
    "Landroid/provider/Browser;deleteFromHistory",
    "Landroid/bluetooth/BluetoothSocket;connect",
    "Landroid/media/Ringtone;stop",
    "Landroid/provider/Settings$Secure;getUriFor",
    "Landroid/os/PowerManager$WakeLock;acquire",
    "Landroid/net/wifi/WifiManager;startScan",
    "Landroid/media/MediaPlayer;stop",
    "Landroid/media/AudioManager;setMicrophoneMute",
    "Landroid/location/LocationManager;addTestProvider",
    "Landroid/telephony/TelephonyManager;getVoiceMailAlphaTag",
    "Landroid/inputmethodservice/KeyboardView;onLongPress",
    "Landroid/provider/Settings$Secure;putString",
    "Landroid/bluetooth/BluetoothDevice;getName",
    "Landroid/location/LocationManager;addGpsStatusListener",
    "Landroid/content/ContentResolver;getSyncAutomatically",
    "Landroid/net/wifi/WifiManager;addNetwork",
    "Landroid/inputmethodservice/KeyboardView;setKeyboard",
    "Landroid/net/wifi/WifiManager;getConnectionInfo",
    "Landroid/net/wifi/WifiManager;getConfiguredNetworks",
    "Landroid/widget/VideoView;setVideoPath",
    "Landroid/inputmethodservice/KeyboardView;onTouchEvent",
    "Landroid/app/KeyguardManager;exitKeyguardSecurely",
    "Landroid/app/WallpaperManager;setResource",
    "Landroid/bluetooth/BluetoothAdapter;startDiscovery",
    "Landroid/telephony/SmsManager;sendTextMessage"
]

interesting_api_20 = [ #at least 20 api per app
    "Ljava/lang/StringBuilder;append",
    "Ljava/lang/StringBuilder;toString",
    "Landroid/app/Activity;onCreate",
    "Ljava/lang/String;equals",
    "Ljava/lang/String;valueOf",
    "Landroid/net/Uri;parse",
    "Ljava/lang/String;substring",
    "Ljava/lang/String;length",
    "Ljava/lang/Integer;parseInt",
    "Ljava/util/List;add",
    "Ljava/lang/Thread;start",
    "Ljava/util/Iterator;next",
    "Ljava/util/Iterator;hasNext",
    "Ljava/util/ArrayList;add",
    "Landroid/app/AlertDialog$Builder;create",
    "Landroid/database/Cursor;getString",
    "Landroid/app/ProgressDialog;show",
    "Landroid/app/AlertDialog$Builder;setPositiveButton",
    "Landroid/app/AlertDialog$Builder;setMessage",
    "Ljava/util/ArrayList;size",
    "Landroid/database/Cursor;close",
    "Landroid/database/Cursor;moveToNext",
    "Landroid/widget/TextView;setText",
    "Landroid/content/Context;getSystemService",
    "Landroid/content/SharedPreferences;edit",
    "Landroid/content/SharedPreferences$Editor;commit",
    "Ljava/lang/Integer;valueOf",
    "Ljava/lang/String;indexOf",
    "Landroid/content/Intent;putExtra",
    "Ljava/io/InputStream;close",
    "Ljava/io/InputStream;read",
    "Ljava/lang/Integer;intValue",
    "Ljava/lang/String;startsWith",
    "Ljava/lang/String;split",
    "Landroid/content/SharedPreferences;getString",
    "Landroid/content/SharedPreferences$Editor;putString",
    "Ljava/lang/String;getBytes",
    "Ljava/lang/Boolean;valueOf",
    "Ljava/lang/Long;valueOf",
    "Landroid/app/Service;onDestroy",
    "Ljava/lang/reflect/Method;invoke",
    "Ljava/lang/Long;longValue",
    "Ljava/lang/Class;forName",
    "Ljava/lang/Boolean;booleanValue",
    "Ljava/lang/Class;getMethod",
    "Landroid/util/Log;d",
    "Landroid/widget/Toast;makeText",
    "Landroid/widget/Toast;show",
    "Landroid/content/Intent;getExtras",
    "Ljava/lang/StringBuffer;toString",
    "Landroid/content/Context;getContentResolver",
    "Landroid/content/Context;startActivity",
    "Landroid/content/Intent;addFlags",
    "Ljava/lang/String;equalsIgnoreCase",
    "Ljava/io/PrintStream;println",
    "Landroid/database/Cursor;moveToFirst",
    "Landroid/webkit/WebSettings;setJavaScriptEnabled",
    "Ljava/lang/String;charAt",
    "Ljava/lang/String;endsWith",
    "Landroid/webkit/WebView;loadUrl",
    "Landroid/app/PendingIntent;getBroadcast",
    "Landroid/content/res/AssetManager;open",
    "Landroid/webkit/WebView;setWebViewClient",
    "Landroid/content/Context;startService",
    "Landroid/app/AlertDialog$Builder;setTitle",
    "Ljava/lang/String;trim",
    "Landroid/app/Activity;onResume",
    "Landroid/app/Service;onCreate",
    "Ljava/net/URLEncoder;encode",
    "Ljava/lang/Long;parseLong",
    "Ljava/lang/Object;toString",
    "Landroid/database/Cursor;getColumnIndex",
    "Landroid/app/ProgressDialog;setMessage",
    "Landroid/os/Handler;sendMessage",
    "Landroid/provider/Settings$Secure;getString",
    "Landroid/content/Context;getResources",
    "Landroid/content/Intent;getAction",
    "Ljava/lang/Thread;sleep",
    "Ljava/util/Set;iterator",
    "Ljava/security/MessageDigest;digest",
    "Ljava/io/FileOutputStream;close",
    "Landroid/util/Log;v",
    "Ljava/io/FileInputStream;close",
    "Ljava/io/InputStreamReader;close",
    "Landroid/content/Context;stopService",
    "Ljava/io/OutputStreamWriter;close",
    "Ljava/io/OutputStreamWriter;write",
    "Ljava/io/OutputStreamWriter;flush",
    "Ljava/io/InputStreamReader;read",
    "Ljava/io/BufferedReader;readLine",
    "Ljava/util/List;size",
    "Landroid/util/Log;e",
    "Ljava/util/List;get",
    "Ljava/lang/System;loadLibrary",
    "Landroid/telephony/SmsMessage;createFromPdu",
    "Landroid/telephony/SmsMessage;getDisplayOriginatingAddress",
    "Ljava/io/File;exists",
    "Landroid/widget/ImageView;setImageResource",
    "Landroid/widget/ImageView;setScaleType",
    "Ljava/lang/System;exit",
    "Landroid/widget/AdapterView;getCount",
    "Landroid/util/Log;w",
    "Landroid/database/sqlite/SQLiteDatabase;execSQL",
    "Landroid/database/sqlite/SQLiteDatabase;query",
    "Landroid/database/Cursor;isClosed",
    "Landroid/database/sqlite/SQLiteDatabase;compileStatement",
    "Landroid/database/sqlite/SQLiteStatement;executeInsert",
    "Ljava/lang/String;replace",
    "Landroid/view/WindowManager;getDefaultDisplay",
    "Ljava/io/BufferedReader;close",
    "Ljava/util/Timer;schedule",
    "Landroid/view/Display;getWidth",
    "Ljava/util/Timer;cancel",
    "Landroid/content/res/Resources;getString",
    "Landroid/content/res/Resources;openRawResource",
    "Ljava/lang/StringBuffer;append",
    "Ljava/lang/Integer;toString",
    "Landroid/app/Activity;onDestroy",
    "Landroid/content/Intent;setData",
    "Ljava/util/regex/Pattern;compile",
    "Ljava/lang/String;replaceAll",
    "Ljava/util/HashMap;put",
    "Ljava/util/HashMap;get",
    "Landroid/content/Intent;setAction",
    "Landroid/widget/EditText;getText",
    "Landroid/os/Handler;post",
    "Landroid/content/ContentResolver;query",
    "Landroid/widget/ImageView;setVisibility",
    "Landroid/app/Activity;onStart",
    "Landroid/view/KeyEvent;getAction",
    "Landroid/view/KeyEvent;getKeyCode",
    "Landroid/app/Activity;dispatchKeyEvent",
    "Landroid/app/AlertDialog$Builder;setNegativeButton",
    "Ljava/lang/String;format",
    "Landroid/app/AlertDialog$Builder;setCancelable",
    "Landroid/preference/PreferenceManager;getDefaultSharedPreferences",
    "Landroid/app/AlertDialog$Builder;setNeutralButton",
    "Landroid/app/Activity;onCreateDialog",
    "Ljava/util/Random;nextInt",
    "Landroid/os/Handler;obtainMessage",
    "Landroid/content/Context;getString",
    "Landroid/app/ProgressDialog;setProgressStyle",
    "Landroid/app/ProgressDialog;setProgress",
    "Landroid/widget/ProgressBar;setProgress",
    "Landroid/widget/ProgressBar;getProgress",
    "Landroid/widget/ProgressBar;incrementProgressBy",
    "Landroid/content/pm/PackageManager;getPackageInfo",
    "Landroid/widget/TextView;setTextColor",
    "Landroid/content/ContentValues;put",
    "Landroid/database/Cursor;getInt",
    "Ljava/util/Calendar;get",
    "Landroid/content/Intent;getBundleExtra",
    "Landroid/telephony/SmsMessage;getOriginatingAddress",
    "Landroid/telephony/SmsMessage;getMessageBody",
    "Lorg/json/JSONTokener;nextValue",
    "Landroid/content/SharedPreferences$Editor;putLong",
    "Landroid/content/SharedPreferences;getLong",
    "Landroid/telephony/TelephonyManager;getNetworkOperator",
    "Ljava/net/HttpURLConnection;setRequestMethod",
    "Ljava/io/FileOutputStream;write",
    "Landroid/content/Intent;setDataAndType",
    "Ljava/io/File;mkdirs",
    "Landroid/net/Uri;fromFile",
    "Landroid/content/Context;getSharedPreferences",
    "Ljava/lang/String;contains",
    "Landroid/content/SharedPreferences;getBoolean",
    "Landroid/content/SharedPreferences$Editor;putBoolean",
    "Ljava/lang/String;toString",
    "Landroid/widget/TextView;getText",
    "Ljava/lang/String;toLowerCase",
    "Landroid/view/MenuItem;getItemId",
    "Landroid/content/pm/PackageManager;getApplicationInfo",
    "Landroid/content/Intent;setClass",
    "Landroid/os/Process;killProcess",
    "Landroid/view/MotionEvent;getAction",
    "Landroid/view/MotionEvent;getX",
    "Landroid/view/MotionEvent;getY",
    "Landroid/view/LayoutInflater;inflate",
    "Landroid/graphics/Paint;setColor",
    "Landroid/content/res/Resources;getDrawable",
    "Landroid/graphics/Paint;setAntiAlias",
    "Landroid/graphics/Paint;setStrokeWidth",
    "Landroid/view/View;getId",
    "Landroid/telephony/TelephonyManager;getSimCountryIso",
    "Landroid/telephony/gsm/SmsMessage;createFromPdu",
    "Landroid/telephony/gsm/SmsMessage;getMessageBody",
    "Landroid/telephony/gsm/SmsMessage;getDisplayOriginatingAddress",
    "Ljava/util/regex/Pattern;matcher",
    "Landroid/os/Handler;postDelayed",
    "Ljava/lang/Object;getClass",
    "Ljava/lang/Class;getName",
    "Ljava/lang/reflect/Field;get",
    "Ljava/io/OutputStream;write",
    "Ljava/io/OutputStream;close",
    "Ljava/io/OutputStream;flush",
    "Ljava/io/File;createNewFile",
    "Ljava/io/File;getPath",
    "Ljava/io/File;getParent",
    "Landroid/content/res/AssetManager;list",
    "Landroid/app/Notification;setLatestEventInfo",
    "Landroid/content/Context;getAssets",
    "Landroid/content/Context;sendBroadcast",
    "Ljava/lang/Runtime;exec",
    "Ljava/lang/Process;waitFor",
    "Landroid/view/Window;setFlags",
    "Ljava/lang/Object;wait",
    "Landroid/app/Dialog;show",
    "Landroid/app/Dialog;setContentView",
    "Ljava/lang/Object;notifyAll",
    "Landroid/app/Dialog;setCancelable",
    "Landroid/app/Dialog;findViewById",
    "Landroid/app/Dialog;setTitle",
    "Landroid/os/PowerManager;newWakeLock",
    "Landroid/app/KeyguardManager;newKeyguardLock",
    "Landroid/content/Intent;getStringExtra",
    "Landroid/app/Activity;onKeyDown",
    "Landroid/app/AlertDialog$Builder;show",
    "Landroid/app/AlertDialog$Builder;setIcon",
    "Landroid/telephony/TelephonyManager;getSimOperatorName",
    "Ljava/util/regex/Pattern;matches",
    "Landroid/content/DialogInterface;dismiss",
    "Ljava/util/StringTokenizer;nextToken",
    "Ljava/util/StringTokenizer;hasMoreTokens",
    "Ljava/util/regex/Matcher;group",
    "Landroid/app/ActivityManager;killBackgroundProcesses",
    "Landroid/location/LocationManager;getProvider",
    "Landroid/media/AudioManager;isWiredHeadsetOn",
    "Landroid/app/KeyguardManager$KeyguardLock;reenableKeyguard",
    "Landroid/speech/SpeechRecognizer;startListening",
    "Landroid/app/DownloadManager;enqueue",
    "Landroid/widget/VideoView;setVideoURI",
    "Landroid/media/Ringtone;setStreamType",
    "Landroid/location/LocationManager;setTestProviderLocation",
    "Landroid/nfc/NfcAdapter;enableForegroundDispatch",
    "Landroid/provider/Browser;getAllBookmarks",
    "Landroid/location/LocationManager;clearTestProviderStatus",
    "Ljava/net/URL;openConnection",
    "Landroid/app/WallpaperManager;setBitmap",
    "Landroid/bluetooth/BluetoothAdapter;getScanMode",
    "Landroid/bluetooth/BluetoothAdapter;isEnabled",
    "Landroid/media/AsyncPlayer;stop",
    "Landroid/telephony/gsm/SmsManager;sendMultipartTextMessage",
    "Landroid/widget/QuickContactBadge;assignContactFromPhone",
    "Landroid/net/wifi/WifiManager;enableNetwork",
    "Landroid/bluetooth/BluetoothDevice;getBondState",
    "Landroid/location/LocationManager;isProviderEnabled",
    "Landroid/content/Context;sendStickyBroadcast",
    "Landroid/bluetooth/BluetoothAdapter;disable",
    "Landroid/app/WallpaperManager;suggestDesiredDimensions",
    "Landroid/provider/Settings$System;putString",
    "Landroid/net/wifi/WifiManager;removeNetwork",
    "Ljava/net/ServerSocket;bind",
    "Landroid/telephony/TelephonyManager;getDeviceSoftwareVersion",
    "Landroid/content/ContentResolver;setMasterSyncAutomatically",
    "Landroid/net/wifi/WifiManager;saveConfiguration",
    "Landroid/telephony/TelephonyManager;getSubscriberId",
    "Landroid/media/MediaRecorder;setAudioSource",
    "Landroid/telephony/TelephonyManager;listen",
    "Ljava/net/URL;getContent",
    "Landroid/accounts/AccountManager;getAccountsByType",
    "Landroid/telephony/gsm/SmsManager;sendTextMessage",
    "Landroid/net/ConnectivityManager;getActiveNetworkInfo",
    "Landroid/media/AudioManager;setBluetoothScoOn",
    "Landroid/net/ConnectivityManager;stopUsingNetworkFeature",
    "Landroid/accounts/AccountManager;removeAccount",
    "Landroid/net/wifi/WifiManager;getWifiState",
    "Landroid/telephony/gsm/SmsManager;sendDataMessage",
    "Landroid/media/AudioManager;setSpeakerphoneOn",
    "Landroid/net/ConnectivityManager;requestRouteToHost",
    "Landroid/location/LocationManager;addNmeaListener",
    "Landroid/telephony/TelephonyManager;getVoiceMailNumber",
    "Landroid/bluetooth/BluetoothAdapter;isDiscovering",
    "Landroid/bluetooth/BluetoothAdapter;getState",
    "Landroid/app/NotificationManager;notify",
    "Landroid/provider/Browser;clearHistory",
    "Landroid/app/KeyguardManager$KeyguardLock;disableKeyguard",
    "Landroid/location/LocationManager;clearTestProviderEnabled",
    "Landroid/bluetooth/BluetoothAdapter;cancelDiscovery",
    "Landroid/media/AsyncPlayer;play",
    "Landroid/provider/Contacts$Settings;getSetting",
    "Landroid/net/wifi/WifiManager;setWifiEnabled",
    "Landroid/location/LocationManager;getProviders",
    "Landroid/os/PowerManager$WakeLock;release",
    "Landroid/location/LocationManager;getLastKnownLocation",
    "Landroid/widget/VideoView;pause",
    "Landroid/media/RingtoneManager;getRingtone",
    "Landroid/app/WallpaperManager;setStream",
    "Landroid/content/Context;setWallpaper",
    "Landroid/telephony/TelephonyManager;getLine1Number",
    "Landroid/net/ConnectivityManager;setNetworkPreference",
    "Landroid/net/wifi/WifiManager$WifiLock;acquire",
    "Landroid/provider/Browser;canClearHistory",
    "Landroid/telephony/TelephonyManager;getNeighboringCellInfo",
    "Landroid/app/ActivityManager;getRunningTasks",
    "Ljava/net/URLConnection;getInputStream",
    "Landroid/os/Vibrator;vibrate",
    "Landroid/media/MediaPlayer;setWakeMode",
    "Landroid/app/WallpaperManager;clear",
    "Landroid/media/MediaPlayer;start",
    "Landroid/app/ActivityManager;getRecentTasks",
    "Landroid/app/ActivityManager;restartPackage",
    "Landroid/content/Context;removeStickyBroadcast",
    "Landroid/provider/Contacts$People;addToMyContactsGroup",
    "Landroid/provider/Browser;clearSearches",
    "Landroid/media/MediaRecorder;setVideoSource",
    "Landroid/provider/Settings$System;getUriFor",
    "Landroid/media/AudioManager;setMode",
    "Landroid/telephony/TelephonyManager;getSimSerialNumber",
    "Landroid/net/wifi/WifiManager$WifiLock;release",
    "Landroid/speech/SpeechRecognizer;setRecognitionListener",
    "Landroid/net/wifi/WifiManager;pingSupplicant",
    "Landroid/net/wifi/WifiManager;getScanResults",
    "Landroid/hardware/Camera;open",
    "Landroid/provider/Browser;getAllVisitedUrls",
    "Landroid/location/LocationManager;setTestProviderEnabled",
    "Landroid/bluetooth/BluetoothAdapter;enable",
    "Landroid/net/wifi/WifiManager;disableNetwork",
    "Landroid/net/wifi/WifiManager;getDhcpInfo",
    "Landroid/telephony/SmsManager;sendMultipartTextMessage",
    "Ljava/net/URL;openStream",
    "Landroid/widget/VideoView;stopPlayback",
    "Landroid/media/AudioManager;isBluetoothA2dpOn",
    "Landroid/accounts/AccountManager;getAccounts",
    "Landroid/telephony/SmsManager;sendDataMessage",
    "Landroid/bluetooth/BluetoothAdapter;listenUsingRfcommWithServiceRecord",
    "Landroid/location/LocationManager;getBestProvider",
    "Landroid/os/Vibrator;cancel",
    "Landroid/net/wifi/WifiManager;isWifiEnabled",
    "Landroid/location/LocationManager;requestLocationUpdates",
    "Landroid/net/ConnectivityManager;getNetworkInfo",
    "Landroid/media/MediaPlayer;release",
    "Landroid/net/wifi/WifiManager;reconnect",
    "Landroid/provider/Contacts$People;createPersonInMyContactsGroup",
    "Landroid/media/MediaPlayer;reset",
    "Landroid/net/wifi/WifiManager;updateNetwork",
    "Landroid/net/wifi/WifiManager;disconnect",
    "Landroid/nfc/NfcAdapter;disableForegroundDispatch",
    "Landroid/media/RingtoneManager;setActualDefaultRingtoneUri",
    "Landroid/bluetooth/BluetoothAdapter;getAddress",
    "Landroid/provider/Contacts$People;queryGroups",
    "Landroid/widget/VideoView;start",
    "Landroid/media/MediaPlayer;pause",
    "Landroid/location/LocationManager;addProximityAlert",
    "Ljava/net/URLConnection;connect",
    "Landroid/widget/VideoView;resume",
    "Landroid/net/ConnectivityManager;startUsingNetworkFeature",
    "Landroid/location/LocationManager;sendExtraCommand",
    "Landroid/bluetooth/BluetoothAdapter;getBondedDevices",
    "Landroid/location/LocationManager;clearTestProviderLocation",
    "Landroid/media/Ringtone;play",
    "Landroid/telephony/TelephonyManager;getCellLocation",
    "Landroid/bluetooth/BluetoothDevice;getBluetoothClass",
    "Landroid/net/wifi/WifiManager;reassociate",
    "Landroid/accounts/AccountManager;clearPassword",
    "Landroid/bluetooth/BluetoothDevice;createRfcommSocketToServiceRecord",
    "Landroid/telephony/TelephonyManager;getDeviceId",
    "Landroid/net/ConnectivityManager;getAllNetworkInfo",
    "Landroid/provider/Settings$System;putInt",
    "Landroid/bluetooth/BluetoothAdapter;getName",
    "Landroid/provider/Browser;deleteFromHistory",
    "Landroid/bluetooth/BluetoothSocket;connect",
    "Landroid/media/Ringtone;stop",
    "Landroid/provider/Settings$Secure;getUriFor",
    "Landroid/os/PowerManager$WakeLock;acquire",
    "Landroid/net/wifi/WifiManager;startScan",
    "Landroid/media/MediaPlayer;stop",
    "Landroid/media/AudioManager;setMicrophoneMute",
    "Landroid/location/LocationManager;addTestProvider",
    "Landroid/telephony/TelephonyManager;getVoiceMailAlphaTag",
    "Landroid/inputmethodservice/KeyboardView;onLongPress",
    "Landroid/provider/Settings$Secure;putString",
    "Landroid/bluetooth/BluetoothDevice;getName",
    "Landroid/location/LocationManager;addGpsStatusListener",
    "Landroid/content/ContentResolver;getSyncAutomatically",
    "Landroid/net/wifi/WifiManager;addNetwork",
    "Landroid/inputmethodservice/KeyboardView;setKeyboard",
    "Landroid/net/wifi/WifiManager;getConnectionInfo",
    "Landroid/net/wifi/WifiManager;getConfiguredNetworks",
    "Landroid/widget/VideoView;setVideoPath",
    "Landroid/inputmethodservice/KeyboardView;onTouchEvent",
    "Landroid/app/KeyguardManager;exitKeyguardSecurely",
    "Landroid/app/WallpaperManager;setResource",
    "Landroid/bluetooth/BluetoothAdapter;startDiscovery",
    "Landroid/telephony/SmsManager;sendTextMessage"
]