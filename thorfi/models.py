"""Database models for the Bull application."""

import datetime

#from flask.ext.sqlalchemy import SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """An admin user capable of viewing reports.

    :param str username: username address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'users'

    username = db.Column(db.String(128), primary_key=True)
    password = db.Column(db.String(128))
    user_domain_name = db.Column(db.String(128))
    #auth_url = db.Column(db.String(128))

    project_name = db.Column(db.String(128))
    project_domain_id = db.Column(db.String(128))
    user_domain_id = db.Column(db.String(128))

    project_id = db.Column(db.String(128))

    urole = db.Column(db.String(128))

    agent_ref = db.Column(db.String(128))
    user_signature = db.Column(db.String(128))

    #TODO: Restore hash password
    def check_password(self, password):
        if (self.password==password):
            return True
        else:
            return False

    def get_id(self):
        """Return the username address to satify Flask-Login's requirements."""
        return self.username

    def __init__(self, username, password, user_domain_name, project_name, project_domain_id, user_domain_id, project_id, urole, agent_ref, user_signature):

        self.username = username
        self.password = password
        self.user_domain_name = user_domain_name
        self.project_name = project_name
        self.project_domain_id = project_domain_id
        self.user_domain_id = user_domain_id
        self.project_id = project_id
        self.urole = urole
        self.agent_ref = agent_ref
        self.user_signature = user_signature


class Campaign(db.Model):

    __tablename__ = "campaigns"

    campaign_id = db.Column(db.Integer, primary_key=True, nullable=False,  autoincrement=True)
    campaign_name = db.Column(db.String(128))
    date = db.Column(db.DateTime, default= datetime.datetime.now())
    net_topology_hash = db.Column(db.String(128), default="None" )
    user_username = db.Column(db.String, db.ForeignKey('users.username'))
    #user = db.relationship(User, backref = db.backref('campaigns_', uselist=True, cascade='delete,all'))

    def __str__(self):
        return self.campaign_name

    def get_id(self):
        return self.campaign_id



class Test(db.Model):

    __tablename__ = "tests"

    ID = db.Column(db.Integer, primary_key=True, nullable=False,  autoincrement=True)
    index = db.Column(db.String(128))
    domain = db.Column(db.String(128))
    resource_type = db.Column(db.String(128))
    resource_name = db.Column(db.String(128))
    resource_faultID = db.Column(db.String(128))
    fault_name = db.Column(db.String(128))
    fault_args = db.Column(db.String(128))
    fault_description = db.Column(db.String(128))
    fault_pattern_name = db.Column(db.String(128))
    fault_pattern_arg1 = db.Column(db.String(128))
    fault_pattern_arg2 = db.Column(db.String(128))
    fault_target_traffic_name = db.Column(db.String(128))
    fault_target_traffic_protocol = db.Column(db.String(128))
    fault_target_traffic_src_ports = db.Column(db.String(128))
    fault_target_traffic_dest_ports = db.Column(db.String(128))
    status = db.Column(db.String(128), default='NotCompleted')
    campaign_id = db.Column(db.String, db.ForeignKey('campaigns.campaign_id'))


class WL_Conf(db.Model):

    __tablename__= "wl_confs"

    ID = db.Column(db.Integer, primary_key=True, nullable=False,  autoincrement=True)
    workload_type = db.Column(db.String(128))
    iperf_client_generator_conf = db.Column(db.Text)
    iperf_server_generator_conf = db.Column(db.Text)
    jmeter_client_generator_conf = db.Column(db.Text)
    campaign_id = db.Column(db.String, db.ForeignKey('campaigns.campaign_id'))


class Time_Conf(db.Model):

    __tablename__="time_confs"

    ID = db.Column(db.Integer, primary_key=True, nullable=False,  autoincrement=True)
    pre_injection_time = db.Column(db.String(128))
    injection_time = db.Column(db.String(128))
    post_injection_time = db.Column(db.String(128))
    campaign_id = db.Column(db.String, db.ForeignKey('campaigns.campaign_id'))


