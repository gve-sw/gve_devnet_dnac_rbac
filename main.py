"""
CISCO SAMPLE CODE LICENSE Version 1.1 Copyright (c) 2022 Cisco and/or its affiliates

These terms govern this Cisco Systems, Inc. ("Cisco"), example or demo source code and its associated documentation 
(together, the "Sample Code"). By downloading, copying, modifying, compiling, or redistributing the Sample Code, 
you accept and agree to be bound by the following terms and conditions (the "License"). If you are accepting the License 
on behalf of an entity, you represent that you have the authority to do so (either you or the entity, "you"). Sample Code 
is not supported by Cisco TAC and is not tested for quality or performance. This is your only license to the Sample Code and 
all rights not expressly granted are reserved.
"""
# import Flask from flask
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
# pass current module (__name__) as argument
# this will initialize the instance
# import required libraries from flask_login and flask_security
from flask_login import LoginManager, login_manager, login_user, login_required
from flask_security import Security, SQLAlchemySessionUserDatastore, current_user
from flask import render_template, redirect, url_for
from flask import request
from dnac_utils import get_sites, add_edge_device, add_border_device, add_control_plane_node, create_fabric_site, provision_device

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"
SQL_USERNAME = ""
SQL_PASSWORD = ""
SQL_IP_ADDRESS = ""
SQL_SCHEMA = ""

# path to sqlite database
# this will create the db file in instance
# if database not present already
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{SQL_USERNAME}:{SQL_PASSWORD}@{SQL_IP_ADDRESS}/{SQL_SCHEMA}"
# needed for session cookies
app.config['SECRET_KEY'] = SQL_PASSWORD
# hashes the password and then stores in the database
app.config['SECURITY_PASSWORD_SALT'] = SQL_PASSWORD
# allows new registrations to application
app.config['SECURITY_REGISTERABLE'] = True
# to send automatic registration email to user
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

db = SQLAlchemy()
db.init_app(app)

# DB Helper Function
def process_sites():
    sites = get_sites()
    for site in sites['response']['sites']:
        if site['groupNameHierarchy'].count('/') == 3:
            h = site['groupNameHierarchy'].split('/')
            area_name = h[1]
            building_name = h[2]
            yield {'id': site['id'], 'floor_name': site['name'], 'area_name': area_name, 'building_name': building_name, 'site_hierarchy': site['groupNameHierarchy']}


# create table in database for assigning roles
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

sites_users = db.Table('sites_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('site_id', db.String(80), db.ForeignKey('site.id')))
# create table in database for storing users
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')
    active = db.Column(db.Boolean())
    # backreferences the user_id from roles_users table
    roles = db.relationship('Role', secondary=roles_users, backref='roled')
    site = db.relationship('Site', secondary=sites_users, backref='sited')



# create table in database for storing roles
class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

# create table in database for storing roles
class Site(db.Model):
    __tablename__ = 'site'
    id = db.Column(db.String(80), primary_key=True)
    area_name = db.Column(db.String(150), unique=True)
    building_name = db.Column(db.String(150), unique=True)
    floor_name = db.Column(db.String(150), unique=True)
    site_hierarchy = db.Column(db.String(500), unique=True)


# creates all database tables
with app.app_context():
    for site in process_sites():
        try:
            db.session.add(Site(**site))
            db.session.commit()
        except Exception as e:
            print(str(e))
    db.create_all()

# load users, roles for a session
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)



# ‘/’ URL is bound with index() function.
@app.route('/')
# defining function index which returns the rendered html code
# for our home page
def index():
    if current_user.is_authenticated:
        return render_template("index.html")
    else:
        return redirect(url_for('signin'))

# signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ""
    # if the form is submitted
    if request.method == 'POST':
        print(request.form)
        # check if user already exists
        user = User.query.filter_by(email=request.form['email']).first()
        msg = ""
        # if user already exists render the msg
        if user:
            msg = "User already exist"
            # render signup.html if user exists
            return render_template('signup.html', msg=msg)

        # if user doesn't exist
        role = Role.query.filter_by(id=request.form['options']).first()
        if not role:
            if request.form['options'] == '1':
                role = Role(id=int(request.form['options']), name="Admin")
                db.session.add(role)
                db.session.commit()
            elif request.form['options'] == '2':
                role = Role(id=int(request.form['options']), name="Engineer")
                db.session.add(role)
                db.session.commit()


        # store the user to database
        user = User(email=request.form['email'], active=1, password=request.form['password'])
        # store the role
        role = Role.query.filter_by(id=request.form['options']).first()
        user.roles.append(role)

        # store the Site
        sites = request.form.getlist('sites')
        for site_id in sites:
            site = Site.query.get(site_id)
            user.site.append(site)

        # commit the changes to database
        db.session.add(user)
        db.session.commit()

        # login the user to the app
        # this user is current user
        login_user(user)
        # redirect to index page
        return redirect(url_for('index'))

    # case other than submitting form, like loading the page itself
    else:
        sites = Site.query.all()
        return render_template("signup.html", msg=msg, sites=sites)


# signin page
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    msg = ""
    if request.method == 'POST':
        # search user in database
        user = User.query.filter_by(email=request.form['email']).first()
        # if exist check password
        if user:
            if user.password == request.form['password']:
                # if password matches, login the user
                login_user(user)
                return redirect(url_for('index'))
            # if password doesn't match
            else:
                msg = "Wrong password"

        # if user does not exist
        else:
            msg = "User doesn't exist"
        return render_template('signin.html', msg=msg)

    else:
        return render_template("signin.html", msg=msg)


@app.route("/provision%20device%20in%20site", methods=['GET', 'POST'])
def provision_device_to_site():
    if request.method == "GET":
        user = User.query.get(current_user.id)
        return render_template("provisionDevice.html", sites=user.site, msg="Provision a device to a site!", status="success")
    if request.method == "POST":
        user = User.query.get(current_user.id)
        site_id = request.form['sites']
        ip_address = request.form['ip_address']

        site = Site.query.get(site_id)
        site_hierarchy = site.site_hierarchy
        response = provision_device(device_ip=ip_address, site_hierarchy=site_hierarchy)
        return render_template("provisionDevice.html", sites=user.site, msg=response['description'], status=response['status'])
        print(response)


@app.route("/add%20device%20to%20site")
def add_device_to_site():
    return render_template("addDeviceToSite.html")

@app.route("/add%20edge%20device", methods=["GET", "POST"])
def add_dna_edge_device():
    if request.method == "GET":
        user = User.query.get(current_user.id)
        return render_template('add_edge_device.html', sites=user.site)
    if request.method == "POST":
        user = User.query.get(current_user.id)
        site_id = request.form['sites']
        ip_address = request.form['ip_address']

        site = Site.query.get(site_id)
        site_hierarchy = site.site_hierarchy
        response = add_edge_device(device_ip=ip_address, site_hierarchy=site_hierarchy)
        return render_template('add_edge_device.html', sites=user.site, msg=response['description'], status=response['status'])
    # add_edge_device()

@app.route("/add%20border%20device", methods=["GET", "POST"])
def add_dna_border_device():
    if request.method == "GET":
        user = User.query.get(current_user.id)
        return render_template("add_border_device.html", sites=user.site)
    if request.method == "POST":
        user = User.query.get(current_user.id)
        form_data = request.form

        external_connectivity_settings = {
            "interfaceName": form_data.get("interfaceName"),
            "interfaceDescription": form_data.get("interfaceDescription"),
            "externalAutonomouSystemNumber": form_data.get("externalAutonomouSystemNumber"),
            "l3Handoff": [
                {
                    "virtualNetwork": {
                        "virtualNetworkName": form_data.get("virtualNetworkName"),
                        "vlanId": form_data.get("vlanId")
                    }
                }
            ],
            "l2Handoff": [
                {
                    "virtualNetworkName": form_data.get("virtualNetworkName"),
                    "vlanName": form_data.get("vlanName")
                }
            ]
        }

        api_data = [{
            "deviceManagementIpAddress": form_data.get("device_management_ip_address"),
            "siteNameHierarchy": form_data.get("sites"),
            "deviceRole": [form_data.get("device_role")],
            "externalDomainRoutingProtocolName": form_data.get("externalDomainRoutingProtocolName"),
            "externalConnectivityIpPoolName": form_data.get("externalConnectivityIpPoolName"),
            "internalAutonomouSystemNumber": form_data.get("internalAutonomouSystemNumber"),
            "borderPriority": form_data.get("borderPriority"),
            "borderSessionType": form_data.get("borderSessionType"),
            "connectedToInternet": form_data.get("connectedToInternet") == "on",
            "sdaTransitNetworkName": form_data.get("sdaTransitNetworkName"),
            "borderWithExternalConnectivity": form_data.get("borderWithExternalConnectivity") == "on",
            "externalConnectivitySettings": [external_connectivity_settings]
        }]

        response = add_border_device(payload=api_data)
        return render_template("add_border_device.html", sites=user.site, msg=response['description'], status=response['status'])


@app.route("/add%20control%20plane%20node", methods=["GET", "POST"])
def add_dna_control_plane_node():
    if request.method == "GET":
        user = User.query.get(current_user.id)
        return render_template("add_control_plane_node.html", sites=user.site)
    if request.method == "POST":
        user = User.query.get(current_user.id)
        site_id = request.form['sites']
        ip_address = request.form['ip_address']

        site = Site.query.get(site_id)
        site_hierarchy = site.site_hierarchy
        response = add_control_plane_node(device_ip=ip_address, site_hierarchy=site_hierarchy)
        return render_template("add_control_plane_node.html", sites=user.site, msg=response['description'], status=response['status'])


@app.route("/create%20fabric%20site", methods=["GET", "POST"])
def create_site():
    # create_fabric_site()
    if request.method == "GET":
        return render_template("createSite.html", msg="Example Site Hierarchy: 'Global/CO/ENGL/Floor-5'", status="success")
    if request.method == "POST":
        site_hierarchy = request.form['site_hierarchy']
        response = create_fabric_site(site_hierarchy=site_hierarchy)
        description = response['description']
        return render_template("createSite.html", msg=description, status=response['status'])


#for running the app
if __name__ == "__main__":
    app.run(debug=True)
