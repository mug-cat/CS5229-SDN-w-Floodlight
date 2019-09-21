#!/usr/bin/python

"""
@Author <Name/Matricno>
Date :
"""


import httplib
import json
import time


class flowStat(object):
    def __init__(self, server):
        self.server = server

    def get(self, switch):
        ret = self.rest_call({}, 'GET', switch)
        return json.loads(ret[2])

    def rest_call(self, data, action, switch):
        path = '/wm/core/switch/'+switch+"/flow/json"
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        #print path
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret

class StaticFlowPusher(object):
    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        #print ret
        conn.close()
        return ret

pusher = StaticFlowPusher('127.0.0.1')
flowget = flowStat('127.0.0.1')

# Block all traffic using dest UDP ports from 1000-1100 between H2 and H3.
def policy1():
    
    for i in range(1000, 1101):
        
        udpPort = str(i)
        nameS2 = "s2Policy1Port" + udpPort
        nameS3 = "s3Policy1Port" + udpPort
        
        pusher.set({
            "switch":"00:00:00:00:00:00:00:02",
            "name":nameS2,
            "eth_type":"0x0800",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "ip_proto":"0x11",
            "udp_dst":udpPort
        })
        pusher.set({
            "switch":"00:00:00:00:00:00:00:03",
            "name":nameS3,
            "eth_type":"0x0800",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "ip_proto":"0x11",
            "udp_dst":udpPort
        })

    pass

# Limit H1 to H2 traffic to 1Mbps.
def policy2():

    S1flowEntry = {
        'switch':"00:00:00:00:00:00:00:01",
        "name":"S1h1toh2QOS",
        "in_port":"1",
        "eth_type":"0x800",
        "ipv4_src":"10.0.0.1",
        "ipv4_dst":"10.0.0.2",
        "active":"true",
        "actions":"set_queue=1,output=2"
    }

    #shouldn't be needed
    
    S2flowEntry = {
        'switch':"00:00:00:00:00:00:00:02",
        "name":"S2h1toh2QOS",
        "priority":"32767",
        "in_port":"2",
        "eth_type":"0x800",
        "ipv4_src":"10.0.0.1",
        "ipv4_dst":"10.0.0.2",
        "active":"true",
        "actions":"set_queue=1,output=1"
    }
    

    pusher.set(S1flowEntry)
    pusher.set(S2flowEntry)
    pass


# For H1 to H3, limit HTTP traffic to 1Mbps for 20Mb and 512Kbps for 10Mb.
def policy3():
    State0Threshold = 20*1000000/8 # Mb not MB
    State1Threshold = State0Threshold/2

    state = 0
    s1 = "00:00:00:00:00:00:00:01"

    entryName = "S1Policy3"
    # initialise
    initialEntry = {
        "switch":s1,
        "name":entryName,
        "in_port":"1",
        "eth_type":"0x0800",
        "ipv4_src":"10.0.0.1",
        "ipv4_dst":"10.0.0.3",
        "ip_proto":"0x06",
        "tcp_dst":"80", # http
        "actions":"set_queue=1,output=3"
    }
    pusher.set(initialEntry)
    tomatch = {
        'eth_type':'0x0x800',
        'in_port':'1',
        'ip_proto':'0x6',
        'ipv4_dst':'10.0.0.3',
        'ipv4_src':'10.0.0.1',
        'tcp_dst':'80'
    }

    def getByteCnt():
        entryList = flowget.get(s1)['flows']
        for entry in entryList:
            if entry['match'] == tomatch:
                return int(entry['byteCount'])
        print('Policy3 entry doesn\'t exist')

    prevByteCount = getByteCnt()
        
    while True:
        time.sleep(0.5)
        byteCount = getByteCnt()
	    byteDiff = byteCount-prevByteCount
        #print("state: {}, byteCount since prev change: {}".format(state,byteDiff))
        if state == 0:
            # check threshold
            if byteDiff >= State0Threshold:
                S1NewFlowEntry = {
                    "switch":s1,
                    "name":entryName,
                    "in_port":"1",
                    "eth_type":"0x0800",
                    "ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3",
                    "ip_proto":"0x06",
                    "tcp_dst":"80",
                    "actions":"set_queue=2,output=3"
                }
                pusher.set(S1NewFlowEntry)                                               
                state = 1
		        prevByteCount = byteCount
        else:
            if byteDiff >= State1Threshold:
                S1NewFlowEntry = {
                    "switch":s1,
                    "name":entryName,
                    "in_port":"1",
                    "eth_type":"0x0800",
                    "ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3",
                    "ip_proto":"0x06",
                    "tcp_dst":"80",
                    "actions":"set_queue=1,output=3"
                }
                pusher.set(S1NewFlowEntry)                                                
                state = 0
		        prevByteCount = byteCount

def staticForwarding():
    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S2->H2 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h2
    
    S1Staticflow1 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h1toh2","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=2"} 
                    
    S1Staticflow2 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h2toh1","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=1"}
    # Define static flow for Switch S2 for packet forwarding b/w h1 and h2
    S2Staticflow1 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h2toh1","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=2"}
    
    S2Staticflow2 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h1toh2","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=1"}
    

    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h3
    S1Staticflow3 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h1toh3","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=3"}
    S1Staticflow4 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h3toh1","cookie":"0",
                    "priority":"1","in_port":"3","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h1 and h3
    S3Staticflow1 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h3toh1","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=2"}
    S3Staticflow2 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h1toh3","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=1"}

    # Below 4 flows are for setting up the static forwarding for the path H2->S2->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h2 and h3
    S2Staticflow3 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h2toh3","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=3"}
    S2Staticflow4 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h3toh2","cookie":"0",
                    "priority":"1","in_port":"3","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h2 and h3
    S3Staticflow3 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h3toh2","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=3"}
    S3Staticflow4 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h2toh3","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=1"}

    #Now, Insert the flows to the switches
   #pusher.set(S1Staticflow1)
    pusher.set(S1Staticflow2)
    pusher.set(S1Staticflow3)
    pusher.set(S1Staticflow4)

    pusher.set(S2Staticflow1)
    #pusher.set(S2Staticflow2)
    pusher.set(S2Staticflow3)
    pusher.set(S2Staticflow4)

    pusher.set(S3Staticflow1)
    pusher.set(S3Staticflow2)
    pusher.set(S3Staticflow3)
    pusher.set(S3Staticflow4)


if __name__ =='__main__':
    staticForwarding()
    policy1()
    policy2()
    policy3()
    pass
