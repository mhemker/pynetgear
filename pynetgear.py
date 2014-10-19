from __future__ import print_function
import requests
import re
import xml.etree.ElementTree as ET
from collections import namedtuple

Device = namedtuple("Device", ["signal","ip","name","mac","type","link_rate"])

class Netgear(object):

    def __init__(self, host, username, password):
        self.soap_url = "http://{}:5000/soap/server_sa/".format(host)
        self.username = username
        self.password = password
        self.logged_in = False
        self.namespaces = {'soap-env':'http://schemas.xmlsoap.org/soap/envelope/',
            'm':'urn:NETGEAT-ROUTER:service:DeviceInfo:1',
            'mconfig':'urn:NETGEAT-ROUTER:service:DeviceConfig:1',
            'mservice':'urn:NETGEAT-ROUTER:service:Time:1',
            'mwlan':'urn:NETGEAT-ROUTER:service:WLANConfiguration:1',
            'mwan':'urn:NETGEAT-ROUTER:service:WANIPConnection:1',
            'mlan':'urn:NETGEAT-ROUTER:service:LANConfigSecurity:1',
            '':''}

    def login(self):
        message = SOAP_LOGIN.format(session_id=SESSION_ID,
                                    username=self.username,
                                    password=self.password)

        success, response = self._make_request(ACTION_LOGIN,
                                               message, False)

        self.logged_in = success

        return self.logged_in

    def get_info(self):
        return self._build_and_make_request3("GetInfo", "DeviceInfo")
            
    def get_config_info(self):
        return self._build_and_make_request3("GetInfo", "DeviceConfig")
            
    def get_ntp_server(self):
        return self._build_and_make_request3("GetInfo", "Time")

    def get_sys_uptime(self):
        return self._build_and_make_request3("GetSysUpTime", "DeviceInfo")
            
    def get_wlan_info(self):
        return self._build_and_make_request3("GetInfo", "WLANConfiguration")

    def get_wlan_WEP_keys(self):
        return self._build_and_make_request3("GetWEPSecurityKeys", "WLANConfiguration")

    def get_wlan_SSID(self):
        return self._build_and_make_request3("GetSSID", "WLANConfiguration")

    def get_wlan_5G_SSID(self):
        return self._build_and_make_request3("Get5GSSID", "WLANConfiguration")

    def get_wlan_channel(self):
        return self._build_and_make_request3("GetChannelInfo", "WLANConfiguration")

    def get_wlan_5g_channel(self):
        return self._build_and_make_request3("Get5GChannelInfo", "WLANConfiguration")

    def get_wlan_region(self):
        return self._build_and_make_request3("GetRegion", "WLANConfiguration")

    def get_wlan_ssid_broadcast(self):
        return self._build_and_make_request3("GetSSIDBroadcast", "WLANConfiguration")

    def get_wlan_wps_mode(self):
        return self._build_and_make_request3("GetWPSMode", "WLANConfiguration")

    def get_wan_connection_type(self):
        return self._build_and_make_request3("GetConnectionTypeInfo", "WANIPConnection")

    def get_wan_connection_ppp_conn_status(self):
        return self._build_and_make_request3("GetPPPConnStatus", "WANIPConnection")

    def get_wan_connection_modem_info(self):
        return self._build_and_make_request3("GetModemInfo", "WANIPConnection")

    def get_wan_connection_dns_lookup_status(self):
        return self._build_and_make_request3("GetDNSLookUpStatus", "WANIPConnection")

    def get_wan_connection_info(self):
        return self._build_and_make_request3("GetInfo", "WANIPConnection")

    def get_wan_port_mapping(self):
        return self._build_and_make_request3("GetPortMappingInfo", "WANIPConnection")

    def get_wan_ethernet_link_status(self):
        return self._build_and_make_request3("GetEthernetLinkStatus", "WANEthernetLinkConfig")

    def get_lan_info(self):
        return self._build_and_make_request3("GetInfo","LANConfigSecurity")

    def get_timezone_info(self):
        return self._build_and_make_request3("GetTimeZoneInfo", "DeviceConfig")

    def get_wpa_security_keys(self):
        return self._build_and_make_request3("GetWPASecurityKeys", "WLANConfiguration")

    def get_dns_masq_device_id(self):
        parms={"NewMACAddress":"default"}
        return self._build_and_make_request3_with_parameters("GetDNSMasqDeviceID", "ParentalControl",parms)

    def get_parental_control_enable_status(self):
        return self._build_and_make_request3("GetEnableStatus", "ParentalControl")

    def get_parental_control_all_mac_addresses(self):
        return self._build_and_make_request3("GetAllMACAddresses", "ParentalControl")

    def get_wlan_guest_access_enabled(self):
        return self._build_and_make_request3("GetGuestAccessEnabled", "WLANConfiguration")

    def get_wlan_guest_access_network_info(self):
        return self._build_and_make_request3("GetGuestAccessNetworkInfo", "WLANConfiguration")

    def get_wlan_ap_info(self):
        return self._build_and_make_request3("GetAPInfo", "WLANConfiguration")

    def get_wlan_info2(self):
        return self._build_and_make_request3("GetWLANnfo", "WLANConfiguration")

    def get_wlan_router_wpa_info(self):
        return self._build_and_make_request3("GetRouterWLANWPAInfo", "WLANConfiguration")

    def get_device_config_is_dlna_enabled(self):
        return self._build_and_make_request3("IsDLNAEnabled", "DeviceConfig")

    def get_device_config_is_dlna_supported(self):
        return self._build_and_make_request3("IsDLNASupported", "DeviceConfig")

    def get_traffic_meter_enabled(self):
        return self._build_and_make_request3("GetTrafficMeterEnabled", "DeviceConfig")

    def get_traffic_meter_options(self):
        return self._build_and_make_request3("GetTrafficMeterOptions", "DeviceConfig")

    def get_traffic_meter_statistics(self):
        return self._build_and_make_request3("GetTrafficMeterStatistics", "DeviceConfig")

    def get_block_device_enable_status(self):
        return self._build_and_make_request3("GetBlockDeviceEnableStatus", "DeviceConfig")

    def get_block_device_options(self):
        return self._build_and_make_request3("GetBlockDeviceOptions", "DeviceConfig")

    def get_device_config_block_site_info(self):
        return self._build_and_make_request3("GetBlockSiteInfo", "DeviceConfig")

    def get_is_5g_supported(self):
        return self._build_and_make_request3("Is5GSupported", "WLANConfiguration")

    def get_5g_info(self):
        return self._build_and_make_request3("Get5GInfo", "WLANConfiguration")

    def get_5g_wpa_security_keys(self):
        return self._build_and_make_request3("Get5GWPASecurityKeys", "WLANConfiguration")

    def get_wlan_5g_guest_access_enabled(self):
        return self._build_and_make_request3("Get5GGuestAccessEnabled", "WLANConfiguration")

    def get_wlan_5g_guest_access_network_info(self):
        return self._build_and_make_request3("Get5GGuestAccessNetworkInfo", "WLANConfiguration")

    def get_attached_devices2(self):
        devices = []

        try:
            re = self._build_and_make_request3("GetAttachDevice", "DeviceInfo")
            data = re["NewAttachDevice"].split("@")

            for i in range(1, int(data[0])):
                device_data = data[i].split(";")
                signal = int(device_data[6]) if device_data[6] else None
                link_rate = int(device_data[5]) if device_data[5] else None
                
                Device = namedtuple("Device", ["signal","ip","name","mac","type","link_rate"])
                atts = [signal] + device_data[1:5] + [link_rate]
                
                devices.append(Device(*atts))
        except:
            print(re)
            
        return devices
    
    def _build_and_make_request(self, message_template, action, xpath_query):
        if not self.logged_in:
            self.login()
        
        action_data = action.split("#")        
        message = message_template.format(session_id=SESSION_ID,method=action_data[0],namespace=action_data[1])
        
        success, response = \
            self._make_request(action, message)
        
        if success:
            root = ET.fromstring(response)
            data = {}
            
            try:
                elem = root.find(xpath_query, self.namespaces)
                for child in elem.findall("*", self.namespaces):
                    data[child.tag] = child.text
            except:
                print(response)
                
            return data
        
    def _build_and_make_request2(self, message_template, action, xpath_query, schema):
        if not self.logged_in:
            self.login()
        
        action_data = action.split("#")        
        message = message_template.format(session_id=SESSION_ID,method=action_data[0],namespace=action_data[1],schema=schema)
        
        success, response = \
            self._make_request(action, message)

        if success:
#            print(response)
            root = ET.fromstring(response)
            data = {}
            
            try:
                elem = root.find(xpath_query, self.namespaces)
                for child in elem.findall("*", self.namespaces):
                    data[child.tag] = child.text
            except:
                print(response)
                
            return data
        
    def _build_and_make_request3(self, methodName, moduleName):
        if not self.logged_in:
            self.login()
        
        action = "urn:NETGEAR-ROUTER:service:{0}:1#{1}".format(moduleName, methodName)
        
        format_params = {}
        format_params["session_id"] = SESSION_ID
        format_params["method"] = methodName
        format_params["module"] = moduleName
        format_params["soap_body"] = ""
        
        message = SOAP_BASE2.format(**format_params)
        
        success, response = \
            self._make_request(action, message)

        if success:
            root = ET.fromstring(response)
            data = {}
            
            try:
                elem = root.find("soap-env:Body", self.namespaces)[0]
                for child in elem.findall("*", self.namespaces):
                    data[child.tag] = child.text
            except:
                print(response)
                
            return data
        
    def _build_and_make_request3_with_parameters(self, methodName, moduleName, params):
        if not self.logged_in:
            self.login()
        
        action = "urn:NETGEAR-ROUTER:service:{0}:1#{1}".format(moduleName, methodName)
        
        format_params = {}
        format_params["session_id"] = SESSION_ID
        format_params["method"] = methodName
        format_params["module"] = moduleName
        format_params["soap_body"] = ""
        
        param_data = ""
        for k in params:
            param_data = param_data + str.format("<{0}>{1}</{0}>", k, params[k]);
        format_params["soap_body"] = param_data

        message = SOAP_BASE2.format(**format_params)
        
        success, response = \
            self._make_request(action, message)

        if success:
            root = ET.fromstring(response)
            data = {}
            
            try:
                elem = root.find("soap-env:Body", self.namespaces)[0]
                for child in elem.findall("*", self.namespaces):
                    data[child.tag] = child.text
            except:
                print(response)
                
            return data
        
    def _make_request(self, action, message, try_login_after_failure=True):
        headers = _get_soap_header(action)

        try:
            req = requests.post(self.soap_url,
                                headers=headers,
                                data=message,
                                timeout=3)

            success = _is_valid_response(req)

            if not success and try_login_after_failure:
                self.login()

                req = requests.post(self.soap_url,
                                    headers=headers,
                                    data=message,
                                    timeout=3)

            return _is_valid_response(req), req.text

        except requests.exceptions.RequestException:
            # Maybe one day we will distinguish between
            # different errors..
            return False, ""

    def dump_data(self, data):
        try:
            for k in data:
                print("    ", k,"-",data[k])
        except:
            print("****", data)

def _get_soap_header(action):
    return {"SOAPAction": action}

def _is_valid_response(resp):
    return (resp.status_code == 200 and 
            "<ResponseCode>000</ResponseCode>" in resp.text)


ACTION_LOGIN = "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate"

# Until we know how to generate it, give the one we captured
SESSION_ID = "A7D88AE69687E58D9A00"

#SESSION_ID = "58DEE6006A88A967E89A"
SOAP_LOGIN = """<?xml version="1.0" encoding="utf-8" ?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID xsi:type="xsd:string" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance">{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<Authenticate>
  <NewUsername>{username}</NewUsername>
  <NewPassword>{password}</NewPassword>
</Authenticate>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_BASE2 = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header><SessionID>{session_id}</SessionID></SOAP-ENV:Header>
<SOAP-ENV:Body>
<M1:{method} xmlns:M1="urn:NETGEAR-ROUTER:service:{module}:1">
{soap_body}
</M1:{method}>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("To test: python pynetgear.py <host> <user> <pass>")
        exit()

    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    netgear = Netgear(host, username, password)

    print("System-Info")
    data = netgear.get_info()
    netgear.dump_data(data)
    
    print("System-Uptime")
    data = netgear.get_sys_uptime()
    netgear.dump_data(data)

    print("Config-Info")
    data = netgear.get_config_info()
    netgear.dump_data(data)

    print("NTP-Server")
    data = netgear.get_ntp_server()
    netgear.dump_data(data)

    print("WLAN")
    data = netgear.get_wlan_info()
    netgear.dump_data(data)

    print("WLAN-WEP-Keys")
    data = netgear.get_wlan_WEP_keys()
    netgear.dump_data(data)

    print("WLAN-SSID")
    data = netgear.get_wlan_SSID()
    netgear.dump_data(data)

    print("WLAN-5G-SSID")
    data = netgear.get_wlan_5G_SSID()
    netgear.dump_data(data)

    print("WLAN-Channel")
    data = netgear.get_wlan_channel()
    netgear.dump_data(data)

    print("WLAN-5G-Channel")
    data = netgear.get_wlan_5g_channel()
    netgear.dump_data(data)

    print("WLAN-Region")
    data = netgear.get_wlan_region()
    netgear.dump_data(data)

    print("WLAN-SSID-Broadcast")
    data = netgear.get_wlan_ssid_broadcast()
    netgear.dump_data(data)

    print("WLAN-WPS-Mode")
    data = netgear.get_wlan_wps_mode()
    netgear.dump_data(data)

    print("WAN-Connection-Type")
    data = netgear.get_wan_connection_type()
    netgear.dump_data(data)

    print("WAN-Connection-Info")
    data = netgear.get_wan_connection_info()
    netgear.dump_data(data)

    print("WAN-Port-Mapping")
    data = netgear.get_wan_port_mapping()
    netgear.dump_data(data)

    print("LAN-Info")
    data = netgear.get_lan_info()
    netgear.dump_data(data)

    print("Config-Info")
    data = netgear.get_timezone_info()
    netgear.dump_data(data)

    # print("Attached-Devices")
    # attached_devices_data2 = netgear.get_attached_devices2()
    # for k in attached_devices_data2:
        # print(k)

    print("WPA-Security-Keys")
    data = netgear.get_wpa_security_keys()
    netgear.dump_data(data)

    print("DNS-Masq-Device-ID")
    data = netgear.get_dns_masq_device_id()
    netgear.dump_data(data)

    print("Parental-Control-Enable-Status")
    data = netgear.get_parental_control_enable_status()
    netgear.dump_data(data)

    print("WLan-Guest-Access-Enabled")
    data = netgear.get_wlan_guest_access_enabled()
    netgear.dump_data(data)

    print("WLan-Guest-Access-Network-Info")
    data = netgear.get_wlan_guest_access_network_info()
    netgear.dump_data(data)

    print("Traffic-Meter-Enabled")
    data = netgear.get_traffic_meter_enabled()
    netgear.dump_data(data)

    print("Traffic-Meter-Options")
    data = netgear.get_traffic_meter_options()
    netgear.dump_data(data)

    print("Traffic-Meter-Statistics")
    data = netgear.get_traffic_meter_statistics()
    netgear.dump_data(data)

    print("Block-Device-Enable-Status")
    data = netgear.get_block_device_enable_status()
    netgear.dump_data(data)

    print("Block-Device-Options")
    data = netgear.get_block_device_options()
    netgear.dump_data(data)

    print("Block-Device-Options")
    data = netgear.get_block_device_options()
    netgear.dump_data(data)

    print("Is-5G-Supported")
    data = netgear.get_is_5g_supported()
    netgear.dump_data(data)

    print("5G-Info")
    data = netgear.get_5g_info()
    netgear.dump_data(data)

    print("5G-WPA-Security-Keys")
    data = netgear.get_5g_wpa_security_keys()
    netgear.dump_data(data)

    print("WLan-5G-Guest-Access-Enabled")
    data = netgear.get_wlan_5g_guest_access_enabled()
    netgear.dump_data(data)

    print("WLan-5G-Guest-Access-Network-Info")
    data = netgear.get_wlan_5g_guest_access_network_info()
    netgear.dump_data(data)

    print("WLan-AP-Info")
    data = netgear.get_wlan_ap_info()
    netgear.dump_data(data)

    print("WLan-Router-WPA-Info")
    data = netgear.get_wlan_router_wpa_info()
    netgear.dump_data(data)

    print("Device-Config-Is-DLNA-Supported")
    data = netgear.get_device_config_is_dlna_supported()
    netgear.dump_data(data)

    print("Device-Config-Is-DLNA-Enabled")
    data = netgear.get_device_config_is_dlna_enabled()
    netgear.dump_data(data)

    print("Device-Config-Block-Site-Info")
    data = netgear.get_device_config_block_site_info()
    netgear.dump_data(data)

    print("Wan-Connection-PPP-Conn-Status")
    data = netgear.get_wan_connection_ppp_conn_status()
    netgear.dump_data(data)

    print("Wan-Connection-Modem-Info")
    data = netgear.get_wan_connection_modem_info()
    netgear.dump_data(data)

    print("Wan-Connection-DNS-Lookup-Status")
    data = netgear.get_wan_connection_dns_lookup_status()
    netgear.dump_data(data)

    print("Wan-Ethernet-Link-Status")
    data = netgear.get_wan_ethernet_link_status()
    netgear.dump_data(data)

    print("WLan-Info2")
    data = netgear.get_wlan_info2()
    netgear.dump_data(data)

    print("Parental-Control-All-MAC-Addresses")
    data = netgear.get_parental_control_all_mac_addresses()
    netgear.dump_data(data)

