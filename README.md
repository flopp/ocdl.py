ocdl.py
=======

Python script for downloading opencaching.de's "saved queries"


    Usage: ocdl.py [options] [ID...]
    
    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -c CONFIGDIR, --configdir=CONFIGDIR
                            specify directory for config files (cookies, login
                            information); default is '~/.ocdl'
      -l, --list            list available queries, do not download them
      -n STYLE, --name=STYLE
                            select naming style of downloaded queries, STYLE={ ID,
                            ID+DATE, NAME, NAME+DATE }, default is 'ID'
      -d TARETDIR, --dir=TARETDIR
                            select target directory for downloaded queries;
                            default is the current directory
      -v, --verbose         print verbose status messages


ocdl.py logs in to opencaching.de using login credentials which are stored
in '~/.ocdl/config.txt' (the actual directory is configurable using the
'--configdir' command line option).

Make sure the directory '~/.ocdl/' (or whatever you chose by
'--configdir') exists and contains the file 'config.txt' with the
following two lines:

    OCDE_LOGIN='username'
    OCDE_PASSWORD='password'

where username and password are your login credentials for opencaching.de

Moreover, ocdl.py stores the login cookie 'cookies.txt' in the selected  
config directory for future logins.
