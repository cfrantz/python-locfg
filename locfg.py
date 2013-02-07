#!/usr/bin/python
###########################################################################
##
## Simplified Python version of CPQLOCFG
## Copyright 2003,2008,2010 Hewlett Packard Development Company, L.P.
##
## You may freely use and modify this program to suit your needs.
##
###########################################################################
import sys
import socket
import re
import urllib2 as u2
from getopt import getopt
import StringIO
import ssl
from xml.etree import ElementTree
try:
    from M2Crypto import SSL
    m2crypto = True
except:
    m2crypto = False


Update_Firmware='''<RIBCL VERSION="2.0">
  <LOGIN USER_LOGIN="Administrator" PASSWORD="password">
    <RIB_INFO MODE="write">
      <UPDATE_RIB_FIRMWARE IMAGE_LOCATION="@FW@"/>
    </RIB_INFO>
  </LOGIN>
</RIBCL>
'''

Get_User='''<RIBCL VERSION="2.0">
  <LOGIN USER_LOGIN="adminname" PASSWORD="password">
  <USER_INFO MODE="read">
    <GET_USER USER_LOGIN="@UN@"/>
  </USER_INFO>
  </LOGIN>
</RIBCL>
'''

Add_User='''<RIBCL VERSION="2.0">
  <LOGIN USER_LOGIN="adminname" PASSWORD="password">
  <USER_INFO MODE="write">
    <ADD_USER 
      USER_NAME="@UN@" 
      USER_LOGIN="@UN@" 
      PASSWORD="@PW@">
      <ADMIN_PRIV value ="Y"/>
      <REMOTE_CONS_PRIV value ="Y"/>
      <RESET_SERVER_PRIV value ="Y"/>
      <VIRTUAL_MEDIA_PRIV value ="Y"/>
      <CONFIG_ILO_PRIV value="Yes"/>
    </ADD_USER>
  </USER_INFO>
  </LOGIN>
</RIBCL>
'''

Mod_User='''<RIBCL VERSION="2.0">
  <LOGIN USER_LOGIN="adminname" PASSWORD="password">
  <USER_INFO MODE="write">
    <MOD_USER USER_LOGIN="@UN@">
      <USER_NAME value="@UN@"/>
      <PASSWORD value="@PW@"/>
      <ADMIN_PRIV value="Yes"/>
      <REMOTE_CONS_PRIV value="Yes"/>
      <RESET_SERVER_PRIV value="Yes"/>
      <VIRTUAL_MEDIA_PRIV value="Yes"/>
      <CONFIG_ILO_PRIV value="Yes"/>
    </MOD_USER>
  </USER_INFO>
  </LOGIN>
</RIBCL>
'''


def usage():
    print """Usage:
locfg -s server [-l logfile] -f inputfile [-u username -p password]
Note: Use -u and -p with caution as command line options are
      visible on Linux.

All options:
    -s, --server:     Specify the server name/IP address
    -l, --logfile:    Where to log output.
    -f, --input:      The input script.
    -u, --username:   Username.
    -p, --password:   Password.
    -i, --iloversion: iLO hardware version (1, 2 or 3).
    -v, --verbose:    Verbose mode.
    -x, --xmlfix:     Do some basic fixups on the returned XML.
    -z, --firmware:   Update the iLO firmware on the target server.
    -m, --m2crypto:   Use the M2Crypto library for SSL connections.
    -a, --adduser:    Add/update a user (-a username:password).
    -h, -?, --help:   This text.
"""
    sys.exit(1)

def usage_err():
    print "Note:"
    print "  Both username and password must be specified with the -u and -p switches."
    print "  Use -u and -p with caution as command line options are visible on Linux."
    sys.exit(1)

# Prepare the script for iLO --
#    substitute in the username and password
#    Strip the local OS EOL convention and add CRLF to each line
def prepare_script(xmlfile, uname=None, pword=None):
    script = ''
    # Prepare a regex for matching the login tag
    logintag = re.compile('<\s*LOGIN[^>]*>', re.I)

    for line in xmlfile:
        # Chomp of any EOL characters
        line = line.rstrip('\r\n')

        # Find login tag and subst username and password
        if (uname and pword and logintag.search(line)):
            line = '<LOGIN USER_LOGIN="%s" PASSWORD="%s">' % (uname, pword)

        # FIXME
        # Special case: UPDATE_RIB_FIRMWARE violates XML.  Send the full
        # UPDATE firmware tag followed by the binary firmware image
        #
        # Note: This is fixed in ribcl_ilo2, and must be fixed there because
        # of how the tags must be sequenced

        if (verbose):
            print line
        script += line + '\r\n'

    return script

# This mechanism is appropriate for communicating with iLO1 and iLO2
def ribcl_ilo2(host, port, script):
    # Open the SSL connection
    try:
        clisock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_m2:
            ctx = SSL.Context()
            ctx.set_options(SSL.op_all | SSL.op_no_sslv2)
            ctx.set_cipher_list('RC4:!MD5')
            client = SSL.Connection(ctx, clisock)
            client.postConnectionCheck = None
            client.connect((host, port))
        else:
            clisock.connect((host, port))
            client = ssl.wrap_socket(clisock)
    except Exception, ex:
        print "ERROR: Failed to establish SSL connection with %s:%d" % (host, port)
        print ex
        sys.exit(1)

    if 'UPDATE_RIB_FIRMWARE' in script:
        # Munge the UPDATE_RIB_FIRMWARE tag to violate XML in the historical way
        m = re.search('''UPDATE_RIB_FIRMWARE\s+IMAGE_LOCATION="(.*)"''', script)
        if m:
            filename = m.group(1)
            fw = file(filename, 'rb').read()
            # Remove the UPDATE_RIB_FIRMWARE tag and replace it with an
            # illegal character that we can later use to split the string.
            script = re.sub('<UPDATE_RIB_FIRMWARE\\s+IMAGE_LOCATION="(.*)"/>', chr(254), script)
            (before, after) = script.split(chr(254))

            # The sequencing of these writes is very important.  The iLO FW
            # doesn't really do proper buffering on some of the items in the XML
            # data stream, so we must insure that certain items are on packet
            # boundaries.
            client.write('<?xml version="1.0"?>\r\n')
            client.write("<LOCFG VERSION=\"2.22\"/>\r\n")
            client.write(before)
            client.write('<UPDATE_RIB_FIRMWARE IMAGE_LOCATION="%s" IMAGE_LENGTH="%d"/>\r\n' % (filename, len(fw)))
            client.write(fw)
            client.write(after)
        else:
            print "Bad firmware update script"
            sys.exit(1)
    else:
        # Send the XML header and begin processing the file
        # Because of the way iLO processes XML, this tag must
        # be sent as a separate packet
        client.write('<?xml version="1.0"?>\r\n')
        client.write("<LOCFG VERSION=\"2.22\"/>\r\n")
        client.write(script)

    # Shutdown our half of the connection
    clisock.shutdown(socket.SHUT_WR)

    # Read back the data until the remote end closes the socket
    data = ''
    while True:
        try:
            d = client.read()
            if not d:
                break
            data += d
        except:
            break

    client.close()
    return data

# This mechanism is appropriate for communicating with iLO3
def ribcl_ilo3(host, port, script):
    urlstr = 'https://%s:%d/ribcl' % (host, port)
    req = u2.Request(url=urlstr, data=script)
    req.add_header('Content-length', len(script))
    data = u2.urlopen(req).read()
    return data

def ribcl_transaction(host, port, uname, pword, xmlfile):
    global ilover
    global xmlfix
    if isinstance(xmlfile, basestring):
        xmlfile = StringIO.StringIO(xmlfile)
    # Prepare the script and do the ribcl transaction
    script = prepare_script(xmlfile, uname, pword)
    if ilover <= 2:
        data = ribcl_ilo2(host, port, script)
    else:
        data = ribcl_ilo3(host, port, script)


    # Now fix up and print the response
    # Remove stray carrage returns
    data = data.replace(chr(13), '')
    if (xmlfix):
        # Remove all the extra XML headers
        data = re.sub("<\\?xml version=\"1.0\"\\?>", "", data)
        if ilover <= 2:
            # iLO1 and 2 can send back a malformed <RIBCL> tag
            data = re.sub("<(RIBCL[^/>]*)/>", "<\\1>", data)
        # Turn the data into a proper XML document
        data = "<?xml version=\"1.0\"?>\n" + "<root>\n" + data + "</root>\n"
    return data


# This little hack reads the RIMP and uses a really simple
# heuristic to guess which version of iLO we're talking to.
def query_ilo_version(host):
    version = 0
    urlstr = 'https://%s/xmldata?item=All' % host
    data = u2.urlopen(urlstr).read()
    m = re.search(r'\(iLO( (\d+))?\)', data)
    if m:
        if m.group(2) is None:
            version = 1
        else:
            version = int(m.group(2))
    return version

# Use the SUDS schemaless XML unmarshaller to turn the XML
# document into a python data structure
def suds_unmarshall(data):
    try:
        from suds.sax.parser import Parser
        from suds.umx.basic import Basic
    except ImportError:
        print "ERROR:  Could not import SUDS."
        print "You must install SUDS for the '-t' option to work"
        print "https://fedorahosted.org/suds/"
        return None

    p = Parser()
    obj = None
    try:
        root = p.parse(string=data).root()
        umx = Basic()
        obj = umx.process(root)
    except Exception, e:
        print "SAX Excpetion:", e
    return obj

def check_error(data):
    if isinstance(data, basestring):
        data = ElementTree.XML(data)

    data = data.findall('RIBCL/RESPONSE')
    for d in data:
        val = int(d.get('STATUS'), 0)
        if val:
            return val, d.get('MESSAGE')
    return None

def do_user(host, port, uname, pword, newuser):
    newuser, newpass = newuser.split(':')
    getuser = re.sub('@UN@', newuser, Get_User)
    data = ribcl_transaction(host, port, uname, pword, getuser)
    print data
    e = ElementTree.XML(data)
    error = check_error(e)
    if error and error[0] == 0x5f:
        return error
    if e.find('RIBCL/GET_USER') is not None:
        update = Mod_User
    else:
        update = Add_User
    update = re.sub('@UN@', newuser, update)
    update = re.sub('@PW@', newpass, update)
    data = ribcl_transaction(host, port, uname, pword, update)
    return check_error(data)


###########################################################################
##
## Process options
##
###########################################################################
host = None
logfile = None
xmlfile = None
uname = None
pword = None
verbose = 0
ilover = 0
help = 0
xmlfix = False
sudstest = False
use_m2 = False
transaction=ribcl_transaction

r = getopt(sys.argv[1:], "a:s:l:f:u:p:i:z:mvxth?", (
    'adduser', 'server=', 'logfile=', 'input=',
    'username=', 'password=', 'iloversion=', 'm2crypto', 'verbose', 'xmlfix', 'firmware=', 'sudstest', 'help')
    )

for (opt, val) in r[0]:
    if (opt == '-s' or opt == '--server'):
        host = val
    elif (opt == '-l' or opt == '--logfile'):
        logfile = val
    elif (opt == '-f' or opt == '--input'):
        xmlfile = file(val, 'r')
    elif (opt == '-u' or opt == '--username'):
        uname = val
    elif (opt == '-p' or opt == '--password'):
        pword = val
    elif (opt == '-i' or opt == '--iloversion'):
        ilover = int(val)
    elif (opt == '-x' or opt == '--xmlfix'):
        xmlfix = True
    elif (opt == '-m' or opt == '--m2crypto'):
        use_m2 = True
    elif (opt == '-v' or opt == '--verbose'):
        verbose += 1
    elif (opt == '-t' or opt == '--sudstest'):
        sudstest = True
    elif (opt == '-z' or opt == '--firmware'):
        fw = re.sub('@FW@', val, Update_Firmware)
        xmlfile = fw
    elif (opt == '-a' or opt == '--adduser'):
        xmlfile = val
        xmlfix = True
        transaction = do_user
    elif (opt == '-h' or opt == '-?' or opt == '--help'):
        help += 1
    else:
        print "Unknown option '%s'" % opt
        help+=1

if (help or not host or not file):
    usage()

# Username and Password must be entered together
if ((uname and not pword) or (pword and not uname)):
    usage_err()

if use_m2 and not m2crypto:
    use_m2 = False
    if verbose:
        print '*' * 70
        print "M2Crypto library requested, but not available."
        print '*' * 70

# Set the default SSL port number if no port is specified
hp = host.split(':')
host = hp[0]
if (len(hp) > 1):
    port = int(hp[1])
else:
    port = 443

# If a logfile is specified, replace stdout with that file
if (logfile):
    sys.stdout = file(logfile, 'w')

# If an iLO version wasn't specified, try to figure it out
if ilover == 0:
    ilover = query_ilo_version(host)
    if verbose:
        if ilover:
            print 'iLO version: %d' % ilover
        else:
            print 'iLO version: Unknown'

data = transaction(host, port, uname, pword, xmlfile)

if (verbose):
    print '*' * 70
    print '*** XML response'
    print '*' * 70
print data

if sudstest:
    if (verbose):
        print '*' * 70
        print '*** Unmarshalled data structure'
        print '*' * 70
    obj = suds_unmarshall(data)
    if obj:
        print obj

sys.exit(0)
# vim: ts=4 sts=4 sw=4 expandtab:
