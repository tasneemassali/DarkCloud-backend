# -*- coding: utf-8 -*-

# -------------------------------------------------------------------------
# AppConfig configuration made easy. Look inside private/appconfig.ini
# Auth is for authenticaiton and access control
# -------------------------------------------------------------------------


from gluon.contrib.appconfig import AppConfig
from gluon.tools import Auth

# -------------------------------------------------------------------------
# This scaffolding model makes your app work on Google App Engine too
# File is released under public domain and you can use without limitations
# -------------------------------------------------------------------------

if request.global_settings.web2py_version < "2.15.5":
    raise HTTP(500, "Requires web2py 2.15.5 or newer")

# -------------------------------------------------------------------------
# if SSL/HTTPS is properly configured and you want all HTTP requests to
# be redirected to HTTPS, uncomment the line below:
# -------------------------------------------------------------------------
# request.requires_https()

# -------------------------------------------------------------------------
# once in production, remove reload=True to gain full speed
# -------------------------------------------------------------------------
configuration = AppConfig(reload=True)

if not request.env.web2py_runtime_gae:
    # ---------------------------------------------------------------------
    # if NOT running on Google App Engine use SQLite or other DB
    # ---------------------------------------------------------------------
    '''db = DAL(configuration.get('db.uri'),
             pool_size=configuration.get('db.pool_size'),
             migrate_enabled=configuration.get('db.migrate'),
             check_reserved=['all'])'''
    db = DAL('mysql://root:1@localhost/darkcloud', pool_size=1, check_reserved=['all'])

else:
    # ---------------------------------------------------------------------
    # connect to Google BigTable (optional 'google:datastore://namespace')
    # ---------------------------------------------------------------------
    db = DAL('google:datastore+ndb')
    # ---------------------------------------------------------------------
    # store sessions and tickets there
    # ---------------------------------------------------------------------
    session.connect(request, response, db=db)
    # ---------------------------------------------------------------------
    # or store session in Memcache, Redis, etc.
    # from gluon.contrib.memdb import MEMDB
    # from google.appengine.api.memcache import Client
    # session.connect(request, response, db = MEMDB(Client()))
    # ---------------------------------------------------------------------

# -------------------------------------------------------------------------
# by default give a view/generic.extension to all actions from localhost
# none otherwise. a pattern can be 'controller/function.extension'
# -------------------------------------------------------------------------
response.generic_patterns = [] 
if request.is_local and not configuration.get('app.production'):
    response.generic_patterns.append('*')

# -------------------------------------------------------------------------
# choose a style for forms
# -------------------------------------------------------------------------
response.formstyle = 'bootstrap4_inline'
response.form_label_separator = ''

# -------------------------------------------------------------------------
# (optional) optimize handling of static files
# -------------------------------------------------------------------------
# response.optimize_css = 'concat,minify,inline'
# response.optimize_js = 'concat,minify,inline'

# -------------------------------------------------------------------------
# (optional) static assets folder versioning
# -------------------------------------------------------------------------
# response.static_version = '0.0.0'

# -------------------------------------------------------------------------
# Here is sample code if you need for
# - email capabilities
# - authentication (registration, login, logout, ... )
# - authorization (role based authorization)
# - services (xml, csv, json, xmlrpc, jsonrpc, amf, rss)
# - old style crud actions
# (more options discussed in gluon/tools.py)
# -------------------------------------------------------------------------

# host names must be a list of allowed host names (glob syntax allowed)
#auth = Auth(db, host_names=configuration.get('host.names'))
# -------------------------------------------------------------------------
# create all tables needed by auth, maybe add a list of extra fields
# -------------------------------------------------------------------------
#auth.settings.extra_fields['auth_user'] = []
#auth.define_tables(username=False, signature=False)

# -------------------------------------------------------------------------
# configure email
# -------------------------------------------------------------------------


# -------------------------------------------------------------------------
# configure auth policy
# -------------------------------------------------------------------------
#auth.settings.registration_requires_verification = False
#auth.settings.registration_requires_approval = False
#auth.settings.reset_password_requires_verification = True

# -------------------------------------------------------------------------  
# read more at http://dev.w3.org/html5/markup/meta.name.html               
# -------------------------------------------------------------------------
response.meta.author = configuration.get('app.author')
response.meta.description = configuration.get('app.description')
response.meta.keywords = configuration.get('app.keywords')
response.meta.generator = configuration.get('app.generator')

# -------------------------------------------------------------------------
# your http://google.com/analytics id                                      
# -------------------------------------------------------------------------
response.google_analytics_id = configuration.get('google.analytics_id')

# -------------------------------------------------------------------------
# maybe use the scheduler
# -------------------------------------------------------------------------
if configuration.get('scheduler.enabled'):
    from gluon.scheduler import Scheduler
  #  scheduler = Scheduler(db, heartbeat=configure.get('heartbeat'))

# -------------------------------------------------------------------------
# Define your tables below (or better in another model file) for example
#
# >>> db.define_table('mytable', Field('myfield', 'string'))
#
# Fields can be 'string','text','password','integer','double','boolean'
#       'date','time','datetime','blob','upload', 'reference TABLENAME'
# There is an implicit 'id integer autoincrement' field
# Consult manual for more options, validators, etc.
#
# More API examples for controllers:
#
# >>> db.mytable.insert(myfield='value')
# >>> rows = db(db.mytable.myfield == 'value').select(db.mytable.ALL)
# >>> for row in rows: print row.id, row.myfield
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# after defining tables, uncomment below to enable auditing
# -------------------------------------------------------------------------
# auth.enable_record_versioning(db)
db.define_table(
   'users',
   Field('firstname','string',length=255, notnull = True, requires=IS_NOT_EMPTY()),
   Field('lastname','string',length=255, notnull = True, requires=IS_NOT_EMPTY()),
   Field('username','string'),
   Field('password', 'password', requires=(IS_NOT_EMPTY())),
   Field('email', 'string',length=255,requires = (IS_EMAIL(),IS_NOT_EMPTY()),unique=True),
   Field('usertype','integer',length=255 ,requires=(IS_IN_SET([1,2,3]),IS_NOT_EMPTY()),notnull = True),
   Field('License_count_endpoint', 'integer'),
   Field('License_count_sensors', 'integer'),
    primarykey=['email'],
migrate=False
)
user = db.users
db.users.email.requires=IS_NOT_IN_DB(db,db.users.email)

db.define_table(
   'endpoint_agents',
   Field('id',length=255),
   Field('ip', notnull = True,requires=IS_NOT_EMPTY()),
   Field('owner_ID', notnull = True,requires=IS_NOT_EMPTY()),
   Field('os_version','string',requires=IS_NOT_EMPTY()),
   Field('enrollement_timestamp','string',requires=(IS_NOT_EMPTY(),IS_DATE('%y-%m-%d'))),
   Field('enrolled_flag', 'boolean'),
    primarykey=['id'],
migrate=False
)

db.define_table(
   'sensors',
    Field('id', length=255,notnull = True),
   Field('ip', notnull = True,requires=IS_NOT_EMPTY()),
   Field('owner_ID',db.users.email, notnull = True,requires=IS_NOT_EMPTY()),
    Field('enrollement_timestamp', 'datetime',requires=(IS_DATE('%y-%m-%d'))),
    Field('enrolled_flag', 'boolean',default='False'),
    primarykey=['id'],
migrate=False

)

db.define_table(
   'honeypots',
    Field('id', length=255,notnull = True),
   Field('ip', notnull = True,requires=IS_NOT_EMPTY()),
   Field('description', notnull = True,requires=IS_NOT_EMPTY()),
    primarykey=['id'],
migrate=False
#migrate=False
)

db.define_table(
   'agents_submissions',
   Field('submitter_id',db.endpoint_agents.id, notnull = True,requires=IS_IN_SET(['agent','sensor','honeypot','user'])),
   Field('submitter_type', notnull = True,requires=IS_NOT_EMPTY()),
   Field('submitted_filehash' ,notnull = True,requires=IS_NOT_EMPTY()),
Field('submitted_timestamp' ,'time',notnull = True,requires=IS_NOT_EMPTY()),
Field('submitted_domain' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['mail','web','endpoint']))),
    Field('sent_to'),
    Field('sent_from'),
    Field('protocol'),
    Field('src_address'),
    Field('dst_address'),
migrate=False
)
db.define_table(
   'sensors_submissions',
   Field('submitter_id',db.sensors.id, notnull = True,requires=IS_IN_SET(['agent','sensor','honeypot','user'])),
   Field('submitter_type', notnull = True,requires=IS_NOT_EMPTY()),
   Field('submitted_filehash' ,notnull = True,requires=IS_NOT_EMPTY()),
Field('submitted_timestamp' ,'time',notnull = True,requires=IS_NOT_EMPTY()),
Field('submitted_domain' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['mail','web','endpoint']))),
    Field('sent_to'),
    Field('sent_from'),
    Field('protocol'),
    Field('src_address'),
    Field('dst_address'),
migrate=False

)


db.define_table(
   'executable_image',
   Field('ex_filehash'),
   Field('filesize','integer'),
   Field('filetype',requires=(IS_IN_SET(['elf','pe','js','pdf','word']),IS_NOT_EMPTY())),
   Field('file_image'),
migrate=False
)

db.define_table(
   'process_traps',
   Field('trap_id',db.users.email, notnull = True,requires=IS_IN_SET(['agent','sensor','honeypot','user'])),
   Field('endpoint_id',db.endpoint_agents.id ,notnull = True),
   Field('process_timestamp' ,'time',notnull = True,requires=IS_NOT_EMPTY()),
   Field('action_taken' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['allow','deny']))),
   Field('reason' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['malware','whitelisted','trusted_ca','unknown']))),
   Field('creator_pid'),
   Field('creator_path'),
   Field('creator_hash'),
   Field('child_id'),
   Field('child_hash'),
   Field('child_image_path'),
migrate=False
#migrate=False
)

db.define_table(
   'url_traps',
   Field('trap_id',db.users.email, notnull = True,requires=IS_IN_SET(['agent','sensor','honeypot','user'])),
   Field('endpoint_id',db.endpoint_agents.id,notnull = True,requires=IS_NOT_EMPTY()),
Field('url_timestamp' ,'time',notnull = True,requires=IS_NOT_EMPTY()),
Field('action_taken' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['allow','deny']))),
Field('reason' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['malicious','blocked']))),
    Field('creator_pid'),
    Field('creator_path'),
    Field('creator_hash'),
    Field('url_string'),
migrate=False
#migrate=False
)

db.define_table(
   'ips_traps',
   Field('trap_id',db.users.email, notnull = True,requires=IS_IN_SET(['agent','sensor','honeypot','user'])),
   Field('endpoint_id',db.endpoint_agents.id,notnull = True,requires=IS_NOT_EMPTY()),
Field('ip_timestamp' ,'time',notnull = True,requires=IS_NOT_EMPTY()),
Field('action_taken' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['allow','deny']))),
Field('reason' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['malicious','blocked']))),
    Field('creator_pid'),
    Field('creator_path'),
    Field('creator_hash'),
    Field('ip_string'),
migrate=False
#migrate=False
)

db.define_table(
   'blacklisted_ip',
    Field('ip_string', notnull = True,requires=IS_NOT_EMPTY()),
   Field('creator_id' ,db.users.email,notnull = True,requires=IS_NOT_EMPTY()),
    Field('creator_comment', notnull=True),
Field('time_created', notnull = True),
Field('type_' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['malicious','blacklist']))),
migrate=False
 #   migrate=False
)

db.define_table(
   'blacklisted_url',
    Field('url_string', notnull = True,requires=IS_NOT_EMPTY()),
    Field('creator_comment', notnull=True),
   Field('creator_id' ,db.users.email,notnull = True,requires=IS_NOT_EMPTY()),
Field('time_created', notnull = True),
Field('type_' ,notnull = True,requires=(IS_NOT_EMPTY(),IS_IN_SET(['malicious','blacklist']))),
   migrate=False
)
db.define_table(
   'blacklisted_exe',
   Field('exec_hash', notnull = True),
    Field('creator_comment', notnull = True),
    Field('time_created', notnull = True),
Field('creator_id' ,db.users.email,notnull = True,requires=IS_NOT_EMPTY()),
    Field('type_', notnull=True, requires=(IS_NOT_EMPTY(), IS_IN_SET(['blacklist', 'whitelist']))),
migrate=False
)
