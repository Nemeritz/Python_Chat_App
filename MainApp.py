#!/usr/bin/python
""" MainApp.py

    COMPSYS302 - Software Design
    Author: Hanliang Ding (hdin898@aucklanduni.ac.nz)

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
from mimetypes import MimeTypes
from operator import itemgetter
from urllib2 import urlopen, HTTPError, URLError
from binascii import hexlify
from cherrypy.process.plugins import Monitor
import calendar
import base64
import os
import cherrypy
import hashlib
import urllib
import urllib2
import json
import sqlite3
import time
from urllib2 import urlopen
import encrypDecryp
import socket
from jinja2 import Environment, FileSystemLoader
from Crypto.PublicKey import RSA
env = Environment(loader=FileSystemLoader('Templates'))

listen_ip = socket.gethostbyname(socket.gethostname())
listen_port = 10002
path = os.path.dirname(os.path.abspath(__file__))
# generates a public key and private key
private = RSA.generate(1024)
public  = private.publickey()

class MainApp(object):
    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 } 
                 
    
    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        tmpl = env.get_template('notification.html')
        cherrypy.response.status = 404
        return tmpl.render(message = '404 Error, Page not Found')


    # login/index page where user can login
    @cherrypy.expose
    def index(self):
        injectself = self.get()
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("DELETE FROM UserKey")
        conn.commit()
        c.execute('''INSERT INTO UserKey(Private, Public) VALUES(?, ?)''',(private.exportKey(), hexlify(public.exportKey('DER'))))
        conn.commit()
        c.close()
        conn.close()
        
        tmpl = env.get_template('login.html')
        
        return tmpl.render()

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, location=None, ip=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password,location,ip)
        if (error == 0):
            cherrypy.session['username'] = username;
            self.validUsers()
            raise cherrypy.HTTPRedirect('/checkOnline')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        self.logout(cherrypy.session.get('username'))
        username = cherrypy.session.get('username')
        if (username == None):
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    
    # Checks if the user is successfully logged in or not with openReportUrl()
    def authoriseUserLogin(self, username=None, password=None, location=None, ip=None):
        response = self.openReportUrl(username, hashlib.sha256(password+"COMPSYS302-2017").hexdigest(), location, ip)
        if response[0] == '0':
            return 0
        else:
            return 1
    # requests a response from the login server, returns 0 if successfully logged in
    def openReportUrl(self, username_input=None, password_input=None, location=None, ip=None):
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("SELECT Public FROM userKey")#gets public key from database and sends it to server
        pubkey = str(c.fetchone())
        c.execute("UPDATE UserKey SET Username=? , Password=? WHERE _rowid_ = '1'",(username_input, password_input))
        conn.commit()
        c.close()
        conn.close()

        values = {'username': username_input, 
            'password': password_input,
            'location' : location,
            'ip' : ip,
            'port' : '10002',
            'pubkey' : pubkey[3:-3]
        }
        try:
            data = urllib.urlencode(values)
            url = "http://cs302.pythonanywhere.com/report"
            req = urllib2.Request(url, data)
            response = urllib2.urlopen(req)
            report_page = response.read()
            return report_page
        except HTTPError:
            return '1'
            
    #The check online page which is also the home page, shows a list of online users
    @cherrypy.expose
    def checkOnline(self):
        if (cherrypy.session.get('username') == None):#Checks for session expiry
            tmpl = env.get_template('notification.html')
            return tmpl.render(message = 'Session Expired, Please login again')
        else:
            #Deletes all old online users and gets new online users list from server
            tmpl = env.get_template('home.html')
            list_users = []
            conn = sqlite3.connect('302Database')
            c = conn.cursor()
            c.execute("DELETE FROM user_info")
            conn.commit()
            c.execute("SELECT Password FROM UserKey WHERE _rowid_ = '1'")
            password = str(c.fetchone())
            c.close()
            conn.close()
    
            data = {'username': cherrypy.session.get('username'), 
                'password': password[3:-3],
                'json': '1'
            }
            
            data = urllib.urlencode(data)
            url = "http://cs302.pythonanywhere.com/getList"
            req = urllib2.Request(url, data)
            response = urllib2.urlopen(req)
            list_page = response.read()
            dict_list = json.loads(list_page)
            #inserting online users into the user_info database
            for i in range (len(dict_list)):
                list_users.append(dict_list[str(i)]['username'])
                conn = sqlite3.connect('302Database')
                c = conn.cursor()
                c.execute("SELECT rowid FROM user_info WHERE Username = ?", (dict_list[str(i)]['username'],))
                check = c.fetchall()
                if len(check) == 0:#Checks for existing row which alraedy has the username
                    try:
                        c.execute('''INSERT INTO user_info(Username, Ip, Port, Location, Time, Key) VALUES(?, ?, ?, ?, ?, ?)''',(dict_list[str(i)]['username'],dict_list[str(i)]['ip'],dict_list[str(i)]['port'],dict_list[str(i)]['location'],dict_list[str(i)]['lastLogin'],dict_list[str(i)]['publicKey']))
                    except KeyError:
                        c.execute('''INSERT INTO user_info(Username, Ip, Port, Location, Time) VALUES(?, ?, ?, ?, ?)''',(dict_list[str(i)]['username'],dict_list[str(i)]['ip'],dict_list[str(i)]['port'],dict_list[str(i)]['location'],dict_list[str(i)]['lastLogin']))
                conn.commit()

            #gets the current user's profile to show on home page so they can edit it
            c.execute("SELECT Name FROM Profile WHERE Username = ?", (cherrypy.session.get('username'),))
            fullname = str(c.fetchall())[4:-4]
            c.execute("SELECT Position FROM Profile WHERE Username = ?", (cherrypy.session.get('username'),))
            position = str(c.fetchall())[4:-4]
            c.execute("SELECT Description FROM Profile WHERE Username = ?", (cherrypy.session.get('username'),))
            description = str(c.fetchall())[4:-4]
            c.execute("SELECT Location FROM Profile WHERE Username = ?", (cherrypy.session.get('username'),))
            location = str(c.fetchall())[4:-4]
            c.execute("SELECT Picture FROM Profile WHERE Username = ?", (cherrypy.session.get('username'),))
            pic = str(c.fetchall())[4:-4]
            if pic == None or pic == "":
                pic = "/img/default.jpg"
            c.close()
            conn.close()
            
            #returns the user's profile and all online users to html via jinja2 to be displayed
            return tmpl.render(mylist=list_users,n=len(list_users), name = fullname, pos = position, des = description, loc = location, pic = pic)

    #receive message API other nodes call on
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self, **kwargs):
        input_data = cherrypy.request.json
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute('''INSERT INTO Messages(Message, Sender, Receiver, Time) VALUES(?, ?, ?, ?)''',(input_data['message'], input_data['sender'], input_data['destination'], input_data['stamp']))
        conn.commit()
        c.close()
        conn.close()
        return '0'
    
    #calls other nodes' receiveMessage API and stores it
    @cherrypy.expose
    def sendMessage(self,  message = None, partner = None):
        sender = cherrypy.session.get('username')
        now = calendar.timegm(time.gmtime())
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        #gets the ip address and port address of the chat receiver from the database
        c.execute("SELECT ip FROM user_info WHERE Username = ?", (partner,))
        ip_address = str(c.fetchone())
        c.execute("SELECT port FROM user_info WHERE Username = ?", (partner,))
        port_address = str(c.fetchone())
        #inserts the message into the message database
        c.execute('''INSERT INTO Messages(Message, Sender, Receiver, Time) VALUES(?, ?, ?, ?)''',(message, cherrypy.session.get('username'), partner, now))
        conn.commit()
        values = {'sender': cherrypy.session.get('username'),
            'destination': partner,
            'message' : message,
            'stamp' : float(now)
        }
        
        c.close()
        conn.close()
        #sends the request in json
        json_values = json.dumps(values)
        data = urllib.urlencode({'data': json_values})
        url = "http://" + ip_address[3:-3] + ":" +port_address[3:-3]+ "/receiveMessage"
        req = urllib2.Request(url,json_values, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        res = response.read()
        #goes back to the chatroom
        raise cherrypy.HTTPRedirect('/chatroom?username=' + partner)
        
    #Opens a chat room page with the other user  
    @cherrypy.expose
    def chatroom(self, username=None):
        #checks for session expiry
        if (cherrypy.session.get('username') == None):
            tmpl = env.get_template('notification.html')
            return tmpl.render(message = 'Session Expired, Please login again')
        else:
            #gets all messages from the current user and chat partner
            tmpl = env.get_template('chatroom.html')
            conn = sqlite3.connect('302Database')
            conn.text_factory = str
            c = conn.cursor()
            #Gets the messages from database
            c.execute("SELECT Message FROM Messages WHERE Sender = ? AND Receiver = ?", (username, cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Messages = rec
            c.execute("SELECT Message FROM Messages WHERE Receiver = ? AND Sender = ?", (username,cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Messages = Messages + rec
            #Gets the message times from database
            c.execute("SELECT Time FROM Messages WHERE Sender = ? AND Receiver = ?", (username, cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Times = rec
            c.execute("SELECT Time FROM Messages WHERE Receiver = ? AND Sender = ?", (username,cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Times = Times + rec
            #Gets the message senders from database
            c.execute("SELECT Sender FROM Messages WHERE Sender = ? AND Receiver = ?", (username, cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Sender = rec
            c.execute("SELECT Sender FROM Messages WHERE Receiver = ? AND Sender = ?", (username,cherrypy.session.get('username')))
            rec = [r[0] for r in c.fetchall()]
            Sender = Sender + rec
            #organizes everything into a tuple and sort by chat time so it can be displayed
            Messages = sorted(zip(Messages,Times, Sender),key=itemgetter(1))
            Messages = Messages[::-1]
            messagelist = []
            person = username
            for x in range (len(Messages)):
                if str(Messages[x][0]) != "None":
                    messagelist.append(str(Messages[x][2])+":" + str(Messages[x][0]))
                else:
                    messagelist.append(str(Messages[x][2])+":" + "File")
            c.close()
            conn.close()
            #returns the list of newest 21 messages into html via jinja2 to display
            return tmpl.render(partner=username, messages=messagelist[0:21], n=21)
            
            
    #Serves non-image file
    @cherrypy.expose
    def fileOpen(self, fname):
        f = open("files/" + fname, "rb")
        data = f.read()
        f.close()
        return data
    
    #Serves a css file from static folder
    @cherrypy.expose
    def css(self, fname):
        cherrypy.request.headers['Content-Type'] = 'text/css'
        f = open("static/" + fname, "r")
        data = f.read()
        f.close()
        return data
        
    #Serves an img file from static folder
    @cherrypy.expose
    def img(self, fname):
        cherrypy.request.headers['Content-Type'] = 'image/png'
        f = open("files/" + fname, "rb")
        data = f.read()
        f.close()
        return data
        
    #Serves a video file from static folder
    @cherrypy.expose
    def video(self, fname):
        cherrypy.request.headers['Content-Type'] = 'video/mp4'
        f = open("files/" + fname, "rb")
        data = f.read()
        f.close()
        return data
    
    #ping for other users to call
    @cherrypy.expose
    def ping(self, sender):
        return '0'
    
    #Opens the show profile page for a particular user
    @cherrypy.expose
    def showProfile(self, username):
        #Checks for session expiry
        if (cherrypy.session.get('username') == None):
            tmpl = env.get_template('notification.html')
            return tmpl.render(message = 'Session Expired, Please login again')
        else:
            #Gets the profile from another node with their getProfile() API
            values = {'sender': cherrypy.session.get('username'),
                'profile_username': username
            }
            
            conn = sqlite3.connect('302Database')
            c = conn.cursor()
            
            #Gets the IP and port addresses
            c.execute("SELECT ip FROM user_info WHERE Username = ?", (username,))
            ip_address = str(c.fetchone())
            c.execute("SELECT port FROM user_info WHERE Username = ?", (username,))
            port_address = str(c.fetchone())
            
            values = json.dumps(values)
            #Gets the profile from another node with their getProfile() API
            url = "http://" + ip_address[3:-3] + ":" +port_address[3:-3]+ "/getProfile"
            try:
                req = urllib2.Request(url,values, {'Content-Type':'application/json'})
                response = urllib2.urlopen(req)
                dict_list = json.loads(response.read())
                
                c.execute("SELECT rowid FROM Profile WHERE Username = ?", (username,))
                check = c.fetchall()
                if len(check) == 0:
                    c.execute('''INSERT INTO Profile(Username, Name, Position, Location, Description, Picture) VALUES(?, ?, ?, ?, ?, ?)''',(username, dict_list['fullname'],dict_list['position'],dict_list['location'],dict_list['description'], dict_list['picture'],))
                else:
                    c.execute('''UPDATE Profile SET Name=?, Position=?, Location=?, Description=?, Picture=? WHERE Username=? ''',( dict_list['fullname'], dict_list['position'],dict_list['location'],dict_list['description'], dict_list['picture'], username,))
                conn.commit()
                c.close()
                conn.close()
            #checks for Errors 
            except HTTPError:
                pass
            except URLError:
                pass
            except KeyError:
                pass
            except TypeError:
				pass
                
            #gets the new profile from the database
            tmpl = env.get_template('profile.html')
            conn = sqlite3.connect('302Database')
            c = conn.cursor()
            c.execute("SELECT Name FROM Profile WHERE Username = ?", (username,))
            fullname = str(c.fetchall())[4:-4]
            c.execute("SELECT Position FROM Profile WHERE Username = ?", (username,))
            position = str(c.fetchall())[4:-4]
            c.execute("SELECT Description FROM Profile WHERE Username = ?", (username,))
            description = str(c.fetchall())[4:-4]
            c.execute("SELECT Location FROM Profile WHERE Username = ?", (username,))
            location = str(c.fetchall())[4:-4]
            c.execute("SELECT Picture FROM Profile WHERE Username = ?", (username,))
            pic = str(c.fetchall())[4:-4]
            c.close()
            conn.close()
            #returns the profile to html via jinja2 for displaying
            return tmpl.render(username=username, name=fullname, pos = position, des=description, loc=location, pic=pic)
    
    #changes the current user profile based on data from the html forms
    @cherrypy.expose
    def changeProfile(self, fullname=None, position=None, description=None, location=None, picture=None):
        tmpl = env.get_template('notification.html')
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("UPDATE Profile SET Name=?, Position=?, Description=?, Location=?, Picture=? WHERE Username = ?", (fullname, position, description, location, picture, cherrypy.session.get('username'),))
        conn.commit()
        c.close()
        conn.close()
        message = "Profile change was successful"
        #go back to the home page
        raise cherrypy.HTTPRedirect('/checkOnline')

    #returns the profile to html via jinja2 for displaying
    def logout(self, username_input):
        if (cherrypy.session.get('username') == None):
            return 1
        else:
            conn = sqlite3.connect('302Database')
            c = conn.cursor()
            c.execute("SELECT Password FROM UserKey WHERE _rowid_ = '1'")
            password = str(c.fetchone())
            c.close()
            conn.close()
            
            print password
            values = {'username': username_input, 
                'password': password[3:-3],
            }
            try:
                data = urllib.urlencode(values)
                url = "http://cs302.pythonanywhere.com/report"
                req = urllib2.Request(url, data)
                response = urllib2.urlopen(req)
                report_page = response.read()
                return 0
            except HTTPError:
                return 1
    
    #Gets the getUser API from the login server and stores it into the database   
    def validUsers(self):
        if (cherrypy.session.get('username') == None):
            return 1
        else:
            try:
                conn = sqlite3.connect('302Database')
                c = conn.cursor()
                c.execute("DELETE FROM registered_user")
                conn.commit()
                url = "http://cs302.pythonanywhere.com/listUsers"
                req = urllib2.Request(url)
                response = urllib2.urlopen(req)
                page = response.read()
                user_list = page.split(",")
                for x in range (len(user_list)):
                    c.execute("SELECT rowid FROM registered_user WHERE Username = ?", (user_list[x],))
                    check = c.fetchall()
                    if len(check) == 0:
                        try:
                            c.execute("INSERT INTO registered_user(Username) VALUES(?)",(user_list[x],))
                        except KeyError:
                            c.execute("INSERT INTO registered_user(Username) VALUES(?)",(user_list[x],))
                conn.commit()
                c.close()
                conn.close()
                return 0
            except HTTPError:
                return 1

    #getProfile for the other nodes to call and returns the current user's profile
    @cherrypy.expose    
    @cherrypy.tools.json_in()
    def getProfile(self, **kwargs):
        input_data = cherrypy.request.json
        if (self.checkValid(input_data['sender']) == 1):
            return '1'
        else:
            conn = sqlite3.connect('302Database')
            c = conn.cursor()
            c.execute("SELECT Name FROM Profile WHERE Username = ?", (input_data['profile_username'],))
            fullname = str(c.fetchall())[4:-4]
            c.execute("SELECT Position FROM Profile WHERE Username = ?", (input_data['profile_username'],))
            position = str(c.fetchall())[4:-4]
            c.execute("SELECT Description FROM Profile WHERE Username = ?", (input_data['profile_username'],))
            description = str(c.fetchall())[4:-4]
            c.execute("SELECT Location FROM Profile WHERE Username = ?", (input_data['profile_username'],))
            location = str(c.fetchall())[4:-4]
       
            data = {'fullname': fullname,
                'position': position,
                'description' : description,
                'location' : location
            }
            
            data = json.dumps(data)
            return data

    #check for valid users based on the table which was created by validUsers()
    def checkValid(self, user):
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("SELECT rowid FROM registered_user WHERE Username = ?", (user,))
        check = c.fetchall()
        c.close()
        conn.close()
        if len(check) != 0:
            return 0
        else:
            return 1
    
    #Lists all available API's
    @cherrypy.expose
    def listAPI(self):
        return "/listAPI /ping [sender] /receiveMessage [sender] [destination] [message] [stamp] /getProfile [profile_username] [sender]"
        + " /receiveFile [sender] [destination] [file] [filename] [content_type] [stamp]"

    #calls other nodes' receiveMessage API and stores it
    @cherrypy.expose
    def sendFile(self,  message = None, partner = None, filename=None):
        sender = cherrypy.session.get('username')
        now = calendar.timegm(time.gmtime())
        file_data = self.fileOpen(filename)

        file_data = base64.b64encode(file_data)
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        
        mime = MimeTypes()
        url = urllib.pathname2url(filename)
        mime_type = mime.guess_type(url)

        #gets the ip address and port address of the chat receiver from the database
        c.execute("SELECT ip FROM user_info WHERE Username = ?", (partner,))
        ip_address = str(c.fetchone())
        c.execute("SELECT port FROM user_info WHERE Username = ?", (partner,))
        port_address = str(c.fetchone())
        #inserts the message into the message database
        c.execute('''INSERT INTO Messages(Message, Sender, Receiver, Time) VALUES(?, ?, ?, ?)''',(message, cherrypy.session.get('username'), partner, now))
        conn.commit()
        values = {'sender': cherrypy.session.get('username'),
            'destination': partner,
            'file' : file_data,
            'filename' : filename,
            'content_type' : mime_type,
            'stamp' : float(now)
        }
        
        c.close()
        conn.close()
        #sends the request in json
        json_values = json.dumps(values)
        data = urllib.urlencode({'data': json_values})
        url = "http://" + ip_address[3:-3] + ":" +port_address[3:-3]+ "/receiveFile"
        req = urllib2.Request(url,json_values, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        res = response.read()
        #goes back to the chatroom
        raise cherrypy.HTTPRedirect('/chatroom?username=' + partner)
        
    #receive file API other nodes call on
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self, **kwargs):
        input_data = cherrypy.request.json
        file_string = base64.b64decode(input_data['file'])
        if (input_data['content_type'] == 'image/jpg') or (input_data['content_type'] == 'image/png') or (input_data['content_type'] == 'image/jpeg') or (input_data['content_type'] == 'video/mp4'):
            f = open('files/' + input_data['filename'], 'wb')
            f.write(file_string)
            f.close()
            return '0'
        else:
            f = open('files/' + input_data['filename'], 'w')
            f.write(file_string)
            f.close()
            return '0'
            
    @cherrypy.expose
    def autoLogoff(self):
        if cherrypy.session.get['username'] == None:
            self.logout()
    
    def get(self):
        return self
        
#    Monitor(cherrypy.engine, object.autoLogoff, 10).subscribe()
    
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/")

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                            'tools.session.timeout': 5,
                            })
    print "========================="
    print "University of Auckland"
    print "COMPSYS302 - Software Design Application"
    print "========================================" 
    
    # Start the web server
    cherrypy.engine.start()
    
    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
