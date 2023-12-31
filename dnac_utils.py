"""
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import os
import time
import requests
import urllib3
import json
import sys
import logging
import datetime
# import yaml

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from dotenv import load_dotenv
from datetime import datetime
from pprint import pprint
from requests.auth import HTTPBasicAuth  # for Basic Auth

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

load_dotenv('environment.env')

DNAC_URL = os.getenv('DNAC_URL')
DNAC_USER = os.getenv('DNAC_USER')
DNAC_PASS = os.getenv('DNAC_PASS')

os.environ['TZ'] = 'America/Los_Angeles'  # define the timezone for PST
time.tzset()  # adjust the timezone, more info https://help.pythonanywhere.com/pages/SettingTheTimezone/

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)


def time_sleep(time_sec):
    """
    This function will wait for the specified time_sec, while printing a progress bar, one '!' / second
    Sample Output :
    Wait for 10 seconds
    !!!!!!!!!!
    :param time_sec: time, in seconds
    :return: none
    """
    print('\nWait for ' + str(time_sec) + ' seconds')
    for i in range(time_sec):
        print('!', end='')
        time.sleep(1)
    return


def get_dnac_token(dnac_auth=DNAC_AUTH):
    """
    Create the authorization token required to access Cisco DNA Center
    Call to Cisco DNA Center - /api/system/v1/auth/login
    :param dnac_auth - Cisco DNA Center Basic Auth string
    :return Cisco DNA Center Token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    response_json = response.json()
    dnac_jwt_token = response_json['Token']
    return dnac_jwt_token


def provision_device(device_ip, site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will provision a network device to a site
    :param device_ip: device management IP address
    :param site_hierarchy: site hierarchy, for example {Global/OR/PDX-1/Floor-2}
    :param dnac_token: Cisco DNA Center auth token
    :return: response, in JSON
    """
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/provision-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_fabric_site(site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will create a new fabric at the site with the hierarchy {site_hierarchy}
    :param site_hierarchy: site hierarchy, for example {Global/OR/PDX-1/Floor-2}
    :param dnac_token: Cisco DNA Center auth token
    :return: response in JSON
    """
    payload = {
        "siteNameHierarchy": site_hierarchy
    }
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/fabric-site'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_edge_device(device_ip, site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will add the device with the management IP address {device_ip}, as an edge device, to the fabric at
    the site with the hierarchy {site_hierarchy}
    :param device_ip: device management IP address
    :param site_hierarchy: fabric site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/edge-device'
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_control_plane_node(device_ip, site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will add the device with the management IP address {device_ip}, as a control-plane node to the fabric
    at the site with the hierarchy {site_hierarchy}
    :param device_ip: device management IP address
    :param site_hierarchy: fabric site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/control-plane-device'
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_border_device(payload, dnac_token=get_dnac_token()):
    """
    This function will add a new border mode device to fabric
    :param payload: the required payload per the API docs
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/border-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_l3_vn(l3_vn_name, site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will create a new L3 virtual network with the name {l3_vn_name} at the site
    with the hierarchy {site_hierarchy}
    :param l3_vn_name: L3 VN name
    :param site_hierarchy: site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/virtual-network'
    payload = {
        'virtualNetworkName': l3_vn_name,
        "siteNameHierarchy": site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_auth_profile(auth_profile, site_hierarchy, dnac_token=get_dnac_token()):
    """
    This function will create a new default auth profile for the fabric at the {site_hierarchy}
    :param auth_profile: auth profile, enum { No Authentication , Open Authentication, Closed Authentication, Low Impact}
    :param site_hierarchy: site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/authentication-profile'
    payload = {
        'siteNameHierarchy': site_hierarchy,
        "authenticateTemplateName": auth_profile
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def get_sites(dnac_token=get_dnac_token()):
    url = DNAC_URL + '/dna/intent/api/v1/topology/site-topology'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    return response_json
