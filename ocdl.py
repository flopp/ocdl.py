#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright: Flopp <mail@flopp-caching.de>
#

#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import cookielib
import urllib
import urllib2
import os
import re
import sys
from optparse import OptionParser, OptionGroup, OptionValueError
from datetime import date

OCDLPY_VERSION="ocdl.py v0.3a 2012-11-03"

def create_directory( d ) :
	if not os.path.isdir( d ) :
		if options.be_verbose :
			print ( "  -- dir '%s' does not exist" % (d) )
			print ( "  -- trying to create dir '%s'" % (d) )
			
		try :
			os.makedirs( d )
		except OSError as e:
			print ( "ERROR: cannot create dir '%s'" % (d) )
			print ( "  -- ", e )
			raise Exception

def naming_style_callback( option, opt_str, value, parser ) :
	if not value in [ "ID", "ID+DATE", "NAME", "NAME+DATE" ] :
		raise OptionValueError( "bad STYLE value for option '%s': '%s'" % ( opt_str, value ) )
	setattr( parser.values, option.dest, value )

additional_help="""
ocdl.py logs in to opencaching.de using login credentials which are stored |
| in '~/.ocdl/config.txt' (the actual directory is configurable using the   |
| '--configdir' command line option).                                       |
|                                                                           |
| You can use the command line option '--setup' to create the configuration |
| directory and to initialize the config file with your login credentials.  |
|                                                                           |
| Alternatively, you can manually create the configuration directory and    |
| the config file:                                                          |
| Make sure the directory '~/.ocdl/' (or whatever you chose by              |
| '--configdir') exists and contains the file 'config.txt' with the         |
| following two lines:                                                      |
|                                                                           |
| OCDE_LOGIN='username'                                                     |
| OCDE_PASSWORD='password'                                                  |
|                                                                           |
| where username and password are your login credentials for opencaching.de |
|                                                                           |
|                                                                           |
| Moreover, ocdl.py stores the login cookie 'cookies.txt' in the selected   |
| config directory for future logins.                                       |
"""

parser = OptionParser( usage = "%prog [options] [ID...]", version = OCDLPY_VERSION, epilog = additional_help )
parser.add_option( "-s", "--setup", action="store_true", dest="perform_setup", default=False, 
				   help="create the necessary directories; ask the user for login credentials" )
parser.add_option( "-c", "--configdir", metavar="CONFIGDIR", dest="config_dir", default="~/.ocdl",
                   help="specify directory for config files (cookies, login information); default is '~/.ocdl'" )
parser.add_option( "-l", "--list", action="store_true", dest="list_only", default=False, 
				   help="list available queries, do not download them" )
parser.add_option( "-n", "--name", metavar="STYLE", 
				   action="callback", callback=naming_style_callback, type="string", dest="naming_style", default="ID",
				   help="select naming style of downloaded queries, STYLE={ ID, ID+DATE, NAME, NAME+DATE }, default is 'ID'" )
parser.add_option( "-d", "--dir", metavar="TARETDIR", dest="target_dir", default=".",
				   help="select target directory for downloaded queries; default is the current directory" )
parser.add_option( "-v", "--verbose", action="store_true", dest="be_verbose", default=False,
				   help="print verbose status messages" )
(options, args) = parser.parse_args()


cookie_jar = cookielib.LWPCookieJar()
opener = urllib2.build_opener( urllib2.HTTPCookieProcessor( cookie_jar ) )
urllib2.install_opener( opener )

headers =  {'User-agent' : 'OCDL.py'}


def store_credentials( filename, login, password ) :
	try :
		f = open( filename, "w" )
		f.write( "OCDE_LOGIN='%s'\n" % (login.encode('utf-8')) )
		f.write( "OCDE_PASSWORD='%s'\n" % (password.encode('utf-8')) )
	except IOError as e:
		if options.be_verbose :
			print ( "  -- WARNING: unable to write to file '%s'" % (filename) )
			print ( "  -- ", e )
	except Exception as e:
		if options.be_verbose :
			print ( "  -- WARNING: unable to write to file '%s'" % (filename) )
			print ( "  -- ", e )

def load_credentials( filename ) :
	if not os.path.isfile( filename ) :
		if options.be_verbose :
			print ( "  -- file '%s' does not exist" % (filename) )
			return (None,None)
	
	try :
		f = open( filename, "r" )
		lines = f.readlines()
		
		# OCDE_LOGIN='username'
		# OCDE_PASSWORD='password'
		
		login=None
		password=None
		
		for line in lines :
			line=line.strip()
			
			if line == "" :
				continue
			elif line.startswith( "#" ) :
				continue
			elif line.startswith( "OCDE_LOGIN='" ) :
				if not( login is None ) :
					if options.be_verbose :
						print ( "  --  WARNING: duplicate 'OCDE_LOGIN' lines in file '%s'" % (filename) )
					return (None,None)
				if not( len(line)>12 ) or not( line.endswith("'") ) :
					if options.be_verbose :
						print ( "  -- WARNING: bad 'OCDE_LOGIN' line in file '%s': %s" % (filename, line) )
					return (None,None)
				login = line[12:-1]
			elif line.startswith( "OCDE_PASSWORD='" ) :
				if not( password is None ) :
					if options.be_verbose :
						print ( "  -- WARNING: duplicate 'OCDE_PASSWORD' lines in file '%s'" % (filename) )
					return (None,None)
				if not( len(line)>15 ) or not( line.endswith("'") ) :
					if options.be_verbose :
						print ( "  -- WARNING: bad 'OCDE_PASSWORD' line in file '%s': %s" % (filename, line) )
					return (None,None)
				password = line[15:-1]
			else :
				if options.be_verbose :
					print ( "  -- WARNING: bad line in file '%s': %s" % (filename, line) )
				return (None,None)
		
		if (login is None) or (password is None) :
			if options.be_verbose :
				print ( "  -- WARNING: no 'OCDE_LOGIN' or 'OCDE_PASSWORD' lines in file '%s'" % (filename) )
			return (None,None)
		
		return (login.decode('utf-8'), password.decode('utf-8'))
		
	except IOError as e:
		if options.be_verbose :
			print ( "  -- WARNING: unable to parse file '%s'" % (filename) )
			print ( "  -- ", e )
		return (None,None)
	except Exception as e:
		if options.be_verbose :
			print ( "  -- WARNING: unable to parse file '%s'" % (filename) )
			print ( "  -- ", e )
		return (None,None)


def parse_queries( data ) :
	res = []
	
	for m in re.finditer( r'<a href="search.php\?queryid=([0-9]*)">([^<]+)</', data ) :
		res.append( m.groups() )
	
	return res

def get_queries( login, password, cookies_filename ) :
	if os.path.isfile( cookies_filename ) :
		if options.be_verbose :
			print ( "  -- loading cookies from '%s'" % cookies_filename )
		
		try :
			cookie_jar.load( cookies_filename )
			
			if options.be_verbose :
				print ( "  -- trying to login via cookies" )
			
			url = 'http://www.opencaching.de/query.php'
			data = None
			
			try :
				req = urllib2.Request( url, data, headers )
				handle = urllib2.urlopen( req )
			except IOError as e:
				print ( "  -- failed to open '%s'" % url )
				print ( "  --", e )
				return None 
			page = handle.read()
			if 'resource2/ocstyle/images/misc/32x32-searchresults.png' in page :
				if options.be_verbose :
					print ( "  -- login via cookies successful" )
				return parse_queries( page )
			else :
				if options.be_verbose :
					print ( "  -- login via cookies failed" )
				cookie_jar.clear()
		except cookielib.LoadError as e:
			print ( "  -- WARNING: failed to load cookies from '%s'" % cookies_filename )
			print ( "  --", e )
		 
	if options.be_verbose :
		print ( "  -- trying login via password" )
	
	if login is None or password is None :
		print ( "ERROR: username and/or password not specified. Please re-run 'ocdl.py' in setup mode (command line option '--setup') to re-enter your login and password." )
		raise Exception
		return None
		 
	url = 'http://www.opencaching.de/login.php'
	data = urllib.urlencode( { 'action' : 'login',
							   'target' : 'query.php',
							   'email' : login.encode('utf-8'),
							   'password' : password.encode('utf-8') } )
	
	try:
		req = urllib2.Request( url, data, headers )
		handle = urllib2.urlopen( req )
	except IOError as e:
		print ( "ERROR: failed to open '%s'" % login_url )
		print ( "  -- ", e )
		raise Exception
		return None
	
	page = handle.read()
	if 'resource2/ocstyle/images/misc/32x32-searchresults.png' in page :
		if options.be_verbose :
			print ( "  -- login via password successful" )
			print ( "  -- storing cookies in '%s'" % cookies_filename )
		
		try :
			cookie_jar.save( cookies_filename );
		except IOError as e:
			print ( "  -- WARNING: failed to store cookies in '%s'" % cookies_filename )
			print ( "  --", e )
		
		return parse_queries( page )
	else :
		print ( "ERROR: login via password failed. Please re-run 'ocdl.py' in setup mode (command line option '--setup') to re-enter your login and password." )
		raise Exception
		return None


def fancy_name( index, name, naming_style ) :
	d = date.today().isoformat()
	s = name.replace( '\\', ' ' ).replace( ' ', '_' )
	if naming_style == 'ID' :
		return index
	elif naming_style == 'ID+DATE' :
		return "%s_%s" % ( index, d )
	elif naming_style == 'NAME' :
		return s
	elif naming_style == 'NAME+DATE' :
		return "%s_%s" % ( s, d )
	else :
		return index


def download_query( index, name, naming_style, target_dir ) :
	create_directory( target_dir )
	
	target = "%s/%s.zip" % ( target_dir, fancy_name( index, name, naming_style ) )
	
	if options.be_verbose :
		print ( "  -- downloading %s/'%s' as %s" % ( index, name, target ) )
	
	url = 'http://www.opencaching.de/search.php?queryid=%s&output=gpx&count=max&zip=1' % index
	data = None
	
	# Open the url
	try :
		req = urllib2.Request( url, data, headers )
		
		if options.be_verbose :
			print ( "  -- downloading " + url )
		handle = urllib2.urlopen( req )

		local_file = open( target, "w" )
		local_file.write( handle.read() )
		local_file.close()

	#handle errors
	except urllib2.HTTPError as e:
		print ( "  -- WARNING: failed to download '%s'" % url )
		print ( "  --", e )
	except urllib2.URLError as e:
		print ( "  -- WARNING: failed to download '%s'" % url )
		print ( "  --", e )
	except IOError as e:
		print ( "  -- WARNING: failed to download '%s' to file '%s'" % ( url, target ) )
		print ( "  --", e )


	

try :
	config_dir = os.path.expanduser( options.config_dir )
	if options.be_verbose :
		print ( "  -- config_path='%s'" % (config_dir) )
	
	create_directory( config_dir )
	
	(login,password) = load_credentials( config_dir + "/config.txt" )
	
	if options.perform_setup :
		print ( "Performing setup." )
		
		login2 = u""
		password2 = u""
		
		if login != None :
			login2 = raw_input( "Enter your username for OC.de [default='%s']: " % (login.encode(sys.stdout.encoding) )).decode( sys.stdin.encoding )
			#print( "Enter your username for OC.de [default='%s']: " % (login) )
			#login2 = sys.stdin.readline().strip()
			if login2 == u"" :
				login2 = login
		else :
			#print( "Enter your username for OC.de:" )
			#login2 = sys.stdin.readline()
			login2 = raw_input( "Enter your username for OC.de: " ).decode( sys.stdin.encoding )
		
		password2 = raw_input( "Enter your password for OC.de: " ).decode( sys.stdin.encoding )
		
		if login != login2 or password != password2 :
			login = login2
			password = password2
			store_credentials( config_dir + "/config.txt", login, password )
		
		print ( "Removing old cookies" );
		try :
			os.remove( config_dir + "/cookies.txt" )
		except Exception:
			print ( "cookie-file not found" )
		print ( "Setup done. You may re-run 'ocdl.py' in normal mode." )
		sys.exit( 0 )
	
	cookies_filename=config_dir + "/cookies.txt"
	
	QUERIES = get_queries( login, password, cookies_filename )
	
	if options.list_only :
		if options.be_verbose :
			print ( "  -- available queries" )
		for (index, name) in QUERIES :
			print ( "%s/'%s'" % ( index, name ) )
	else :
		if args == [] :
			if options.be_verbose :
				print ( "  -- downloading all queries" )
			for (index, name) in QUERIES :
				download_query( index, name, options.naming_style, options.target_dir )
		else :
			if options.be_verbose :
				print ( "  -- downloading specified queries" )
			
			for aindex in args :
				found = False
				for (index, name) in QUERIES :
					if aindex == index :
						download_query( index, name, options.naming_style, options.target_dir )
						found = True
						break
				if not found :
					print ( "  -- WARNING: specifyed query with index '%s' not found" % aindex )
except Exception as e:
	print ( "too bad, ocdl.py aborted due to an error!" )
	print ( e )
