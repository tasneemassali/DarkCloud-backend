# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------
#login function
from datetime import datetime
def login():
    message=''
    message1=''
    #form of login
    form = SQLFORM.factory(db.users.email,db.users.password)
    #to check if the user in the system
    rows = db(db.users.email == request.vars.email)
    count=rows.count()
    if count>0:
        userss=rows.select(db.users.ALL)
        for row in userss:
            #to check if the password is right
            if request.vars.password==row.password:
                #check the type of user to open the appropriate page
                if row.usertype== 1:
                    session.user=row
                    redirect(URL(f='admin',vars={'showtable':1},args=['user']))
                elif row.usertype==2:
                    session.user = row
                    redirect(URL(f='subscriber',args=['endpoints']))
                elif row.usertype == 3:
                    session.user = row
                    redirect(URL('analyst'))
            else:
                message1="wrong password"
    else:
        message='wrong email'

    return dict (form=form,message=message,message1=message1)

#Admin page controller
def admin():
    #initial page to be loaded
    type = 'Analysts'
    deletidd='no'
    userstemp=''
    addform=''
    grid=''
    #if there is arguments then an action happened
    if request.args:
        session['vars']=request.vars
        session['showtable'] = request.vars['showtable']
        session['action']=request.args[0]
    #check the tyype of action needed then do it
    """types of actions:
    >>honeypots: to get all honeypots from the database
    >>user: to get the users based on the argument which specify type of user to be retrived
    >>statstics: to get some data from database then calculate avg
    """
    if session['action']=='honeypots':
        type='Honeypots'
        userstemp = db(db.honeypots).select(db.honeypots.ALL)
        addform=SQLFORM.factory(db.honeypots.ip,db.honeypots.description)
        if addform.process().accepted:
            db.honeypots.insert(ip=request.vars.ip,description=request.vars.description)
            redirect(URL(f='admin', args=['honeypots']))
        elif addform.errors:
            response.flash = "form with errors"

        if session.vars['deletid1'] != None:
            db(db.honeypots.id == session.vars['deletid1']).delete()
            redirect(URL(f='admin',args=['honeypots']))
            print 'deleted'

    elif session['action']=='user':
            if request.vars['deletid'] != None:
                db(db.users.email==request.vars['deletid']).delete()
                redirect(URL(f='admin',vars={'showtable':session['usertype']},args=['user']))

            if(session['showtable']=='1'):
                type='Admins'
                userstemp=db(db.users.usertype == '1').select(db.users.ALL)
                session['usertype']='1'
            elif session['showtable']=='2':
                type = 'Subscribers'
                userstemp=db(db.users.usertype == '2').select(db.users.ALL)
                session['usertype']='2'

            elif session['showtable']=='3':
                type = 'Analysts'
                userstemp = db(db.users.usertype == '3').select(db.users.ALL)
                session['usertype']='3'

            addform = SQLFORM.factory(db.users.firstname,db.users.lastname,db.users.username, db.users.email,db.users.password)
            form=SQLFORM.grid(db.users)
            if addform.process().accepted:
                if(len(request.vars.password)>0):
                    id=db.users.insert(firstname=request.vars.firstname,lastname=request.vars.lastname,username=request.vars.username,email=request.vars.email,password=request.vars.password,usertype=session['usertype'])
                    redirect(URL(f='admin', vars={'showtable': session['usertype']},args=['user']))
                else:
                    message='password'

            elif addform.errors:
                response.flash="form with errors"
    else:
        all= db(db.users).count()
        analystscount= db(db.users.usertype == '3').count()
        subscriberscount = db(db.users.usertype == '2').count()
        adminscount = db(db.users.usertype == '1').count()
        print all
        print subscriberscount
        if all!=0:
            session['avganalysts']=(float(analystscount) /float(all))*100
            session['avgsubscribers'] = (float(subscriberscount) /float(all))*100
            session['avgadmins'] = (float(adminscount) /float(all))*100
        else:
            session['avganalysts'] = 0
            session['avgsubscribers'] = 0
            session['avgadmins'] = 0

    return dict(usertype=type,user=session.user.username,userstemp=userstemp,form=addform,grid=grid)

#subscrriber page controller
def subscriber():
    #initial page to be loaded is endpoints
    session['action']='endpoints'
    devicestemp = ''
    addform = ''
    type='Endpoints'
    session['vars']=None
    if request.args:
        session['vars'] = request.vars
        session['type'] = request.vars['type']
        session['action'] = request.args[0]


    print session['action']
    if session['action'] == 'endpoints':
        type = 'Endpoints'
        devicestemp = db(db.endpoint_agents).select(db.endpoint_agents.ALL)

        if session.vars['deletid'] != None:
            db(db.endpoint_agents.id == session.vars['deletid']).delete()
            redirect(URL(f='subscriber', args=['endpoints']))
    elif session['action']=='add_endpoints':
        addform = SQLFORM.factory(db.endpoint_agents.ip, db.endpoint_agents.os_version,
                                  db.endpoint_agents.enrolled_flag)
        if addform.process().accepted:
            id = db.endpoint_agents.insert(ip=request.vars.ip, os_version=request.vars.os_version,
                                           owner_ID=session['user'].email,
                                           enrollement_timestamp=datetime.now(), enrolled_flag=request.vars.enrolled_flag)
            redirect(URL(f='subscriber', args=['endpoints']))
        elif addform.errors:
            response.flash = "form with errors"
            redirect(URL(f='subscriber', args=['endpoints']))

            # print session['action']
    elif session['action'] == 'sensors':
        if request.vars['deletid'] != None:
            db(db.sensors.id == request.vars['deletid']).delete()
            redirect(URL(f='subscriber', args=['sensors']))
        type = 'Sensors'
        devicestemp = db(db.sensors).select(db.sensors.ALL)


    elif session['action']=='add_sensors':
        addform = SQLFORM.factory(db.sensors.ip,
                                  db.sensors.enrolled_flag)
        if addform.process().accepted:
            id = db.sensors.insert(ip=request.vars.ip, owner_ID=session['user'].email,
                                   enrollement_timestamp=request.vars.enrollement_timestamp,
                                   enrolled_flag='True')
            redirect(URL(f='subscriber', args=['sensors']))

    elif session['action'] == 'statistics':
        print session['type']
        if(session['type']=="endpoints"):
            all=db(db.endpoint_agents).count()
            type='endpoints'
            session['all'] = 0.5
        else:
            all = db(db.sensors).count()
            session['all']=0.5
            sensorscount = db(db.sensors).count()
            endpointscount = db(db.endpoint_agents).count()

            if all != 0:
                session['avgsensors'] = (float(sensorscount) / float(all)) * 100
                session['avgendpoints'] = (float(endpointscount) / float(all)) * 100

            else:
                session['avgsensors'] = 0
                session['avgendpoints'] = 0

    elif session['action'] == 'sensors_submissions':
            type = 'Submissions'
            devicestemp = db(db.sensors_submissions).select(db.sensors_submissions.ALL)
    elif session['action'] == 'agents_submissions':
            type = 'Submissions'
            devicestemp = db(db.agents_submissions).select(db.agents_submissions.ALL)
    elif session['action'] == 'events':
            type = 'Submissions'
            devicestemp = db(db.sensors_submissions).select(db.sensors_submissions.ALL)
    return dict(usertype=type, user=session.user.username, devicestemp=devicestemp, form=addform)


def analyst():
    message=request.vars
    return dict(user=session.username,message=message)


def signout():
    session['user']=''
    redirect(URL(f=login))

# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """

    return dict(form=auth())

# ---- action to server uploaded static content (required) ---
@cache.action()
def download():
    """
    allows downloading of uploaded files
    http://..../[app]/default/download/[filename]
    """
    return response.download(request, db)
