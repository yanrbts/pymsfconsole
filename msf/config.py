# -*- coding: utf-8 -*-
class CONFIG():
	"""docstring for CONFIG"""
	
	_VERSION_		= '1.0.0'
	_NAME_			= 'pymsf'
	ROOT_PATH		= 'msf/'
	DEBUG_FLAG		= True
	TIME_OUT		= 30
	DB_ACCESS		= True
	PROXY			= None #'http://127.0.0.1:8080/'
	SOCKS			= None
	DATA_PATH		= ROOT_PATH + 'data'
	MODULES_PATH	= ROOT_PATH + 'modules'
	TMP_PATH		= ROOT_PATH + 'output'
	FILE_PATH		= DATA_PATH + '/file'
	EXTENSION		= ["pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx" , "odp", "ods"]
	COLOR_STATUS	= '1;34m'
	COLOR_SUCCESS	= '1;32m'
	COLOR_ERROR		= '1;31m'
	COLOR_CMD		= '1;33m'
	GMAIL_ACCOUNT	= ['unknow.checker@gmail.com','checker.']
	IP_WHITE_LIST	= ['8.8.8.8']
	QUOTES          = ['I\'ll be back.', 'GoodBye !']
