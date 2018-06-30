# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------
#login function
from datetime import datetime
from collections import OrderedDict

import copy


def index():
    redirect(URL(f='login'))

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
    siglist=''
    processes={}
    session['levels']=0
    type1='Endpoints'
    exe_list=OrderedDict()
    session['vars']=None
    session['hash']=request.vars['hashsearch']
    session ['levels']=request.vars['level']
    if request.args:
        session['vars'] = request.vars
        session['type'] = request.vars['type']
        session['action'] = request.args[0]

    print request.vars
    print session['action']
    if session['action'] == 'endpoints':
        type1= 'Endpoints'
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
        type1 = 'Sensors'
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
            type1='endpoints'
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
            type1 = 'Submissions'
            devicestemp = db(db.sensors_submissions).select(db.sensors_submissions.ALL)
    elif session['action'] == 'agents_submissions':
            type1 = 'Submissions'
            devicestemp = db(db.agents_submissions).select(db.agents_submissions.ALL)
    elif session['action'] == 'events':
            type1 = 'Submissions'
            devicestemp = db(db.sensors_submissions).select(db.sensors_submissions.ALL)

    elif session['action']=='sig-url-blacklist':
        type1='URLs'
        if request.vars['id']!=None:
            db(db.blacklisted_url.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-url-blacklist']))
        addform = SQLFORM.factory(db.blacklisted_url.url_string, db.blacklisted_url.creator_comment)
        if addform.process().accepted:
            id = db.blacklisted_url.insert(url_string=request.vars.url_string, creator_comment=request.vars.creator_comment,
                                           creator_id=session['user'].email,type_='blacklist')
            redirect(URL(f='subscriber', args=['sig-url-blacklist']))
        siglist =db(db.blacklisted_url.type_=='blacklist').select(db.blacklisted_url.ALL)

    elif session['action']=='sig-url-malicious':
        type1='URLs'
        addform = SQLFORM.factory(db.blacklisted_url.url_string, db.blacklisted_url.creator_comment)
        if request.vars['id']!=None:
            db(db.blacklisted_url.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-url-malicious']))

        if addform.process().accepted:
            id = db.blacklisted_url.insert(url_string=request.vars.url_string,
                                           creator_comment=request.vars.creator_comment,
                                           creator_id=session['user'].email, type_='malicious')
            redirect(URL(f='subscriber', args=['sig-url-malicious']))

        siglist =db(db.blacklisted_url.type_=='malicious').select(db.blacklisted_url.ALL)

    elif session['action']=='sig-ip-blacklist':
        type1='IPs'
        addform = SQLFORM.factory(db.blacklisted_ip.ip_string, db.blacklisted_ip.creator_comment)
        if request.vars['id']!=None:
            db(db.blacklisted_ip.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-ip-blacklist']))
        if addform.process().accepted:
            id = db.blacklisted_ip.insert(ip_string=request.vars.ip_string,
                                           creator_comment=request.vars.creator_comment,
                                           creator_id=session['user'].email, type_='blacklist')
            redirect(URL(f='subscriber', args=['sig-ip-blacklist']))

        siglist =db(db.blacklisted_ip.type_=='blacklist').select(db.blacklisted_ip.ALL)
    elif session['action']=='sig-ip-malicious':
        type1='IPs'
        addform = SQLFORM.factory(db.blacklisted_ip.ip_string, db.blacklisted_ip.creator_comment)
        if request.vars['id']!=None:
            db(db.blacklisted_ip.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-ip-malicious']))
        if addform.process().accepted:
            id = db.blacklisted_ip.insert(ip_string=request.vars.ip_string,
                                           creator_comment=request.vars.creator_comment,
                                           creator_id=session['user'].email, type_='malicious')
            redirect(URL(f='subscriber', args=['sig-ip-malicious']))

        siglist =db(db.blacklisted_ip.type_=='malicious' and db.blacklisted_ip.creator_id == session['user'].email).select(db.blacklisted_ip.ALL)

    elif session['action']=='sig-exe-blacklist':
        type1='Executables'
        addform = SQLFORM.factory(db.blacklisted_exe.exec_hash, db.blacklisted_exe.creator_comment)
        if request.vars['id']!=None:
            db(db.blacklisted_exe.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-exe-blacklist']))
        if addform.process().accepted:
            id = db.blacklisted_exe.insert(exec_hash=request.vars.exec_hash,
                                          creator_comment=request.vars.creator_comment,
                                          creator_id=session['user'].email, type_='blacklist')
            redirect(URL(f='subscriber', args=['sig-exe-blacklist']))

        siglist =db(db.blacklisted_exe.type_=='blacklist').select(db.blacklisted_exe.ALL)
    elif session['action']=='sig-exe-whitelist':
        type1='Executables'
        addform = SQLFORM.factory(db.blacklisted_exe.exec_hash,db.blacklisted_exe.creator_comment)
        if request.vars['id']!=None:
            db(db.blacklisted_exe.id == request.vars['id']).delete()
            redirect(URL(f='subscriber', args=['sig-exe-whitelist']))
        if addform.process().accepted:
            print request.vars
            id = db.blacklisted_exe.insert(exec_hash=request.vars.exec_hash,
                                          creator_comment=request.vars.creator_comment,
                                          creator_id=session['user'].email, type_='whitelist')
            redirect(URL(f='subscriber', args=['sig-exe-whitelist']))
        elif addform.errors:
            print addform.errors
            print 'error11'
        else:
            print 'error'

        siglist =db(db.blacklisted_exe.type_=='whitelist').select(db.blacklisted_exe.ALL)

    elif session['action'] == 'monitor-exe':
        if request.vars['id']!=None:
            processes=db(db.process_traps.id==request.vars['id']).select(db.process_traps.ALL)
        if session['hash'] != None:
            print 'hi'
            hash=session['hash']
            pid = db(db.process_traps.child_hash == hash).select(db.process_traps.ALL)
            pidlist=[]
            pidlist1=[]
            for row in pid:
                exe_list[str(row.id)] = OrderedDict()
                exe_list[str(row.id)][str(row.id)]=dict(row)
                print exe_list
                allchild = db(db.process_traps.creator_pid == row.child_id).select(db.process_traps.ALL)
                for child in allchild:
                    exe_list[str(row.id)][str(child.id)]=dict(child)
                    pidlist.append(child.child_id)
                    pidlist1.append(str(child.id))
                print exe_list
               # print type(exe_list[row.child_id])
                break
            pidlist2=[]
            c=0

            for i in range(int(session['levels'])-1):
                for pid in pidlist:
                    if pid==None or pidlist1[c]==None :
                        break
                    exe_list[pidlist1[c]]=OrderedDict()
                    allchild = db(db.process_traps.creator_pid == pid).select(db.process_traps.ALL)
                    if allchild == None:
                        break
                    for child in allchild:
                        exe_list[pidlist1[c]][str(child.id)]= dict(child)
                        pidlist2.append(child.child_id)
                    c+=1
                pidlist=pidlist2
        print request.vars

    return dict(usertype=type1, user=session.user.username, devicestemp=devicestemp, form=addform, siglist=siglist,exelist=exe_list,processlist=processes)


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
        @auth.requssssires_permission('read','table name',record_id)
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
