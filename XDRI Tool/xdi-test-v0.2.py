import json
import binascii
import re
import argparse
import traceback
import errno
import gzip
import statistics
import select
import ipaddress
import random
import sys
import colorama
import requests
import platform

# pypi
import psutil

# from redis import Redis
import scapy.packet

# Own imports
from my_dns import *
from rate import rate, preprocess

TOOL_NAME = "XDI-Test v0.2"

colorama.init()

DEFAULT_TESTS = [{
'expected': [{
'info': 'bad_cname',
 'type': 5,
 'testtype': 'critical',
 'data': '(?i)^[a-z0-9]+.works.cnametest.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[a-z0-9]+.works.cnametest.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.89$'
}],
 'type': 1,
 'edns': False,
 'qname': '$HASH.cnametest.test2.xdi-attack.net',
 'name': 'cname-trigger',
 'expected_result': True,
 'is_attack': False
},
 {
'expected': [{
'info': 'cname_merge',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[a-z0-9]+.cnametest.test2.xdi-attack.net.$',
 'data': '^141.12.174.89$'
}],
 'type': 1,
 'edns': False,
 'qname': '$HASH.cnametest.test2.xdi-attack.net',
 'name': 'cname-merge',
 'expected_result': False,
 'is_attack': False,
 'detail': 'This resolver merges CNAME chains into synthesized A records.\nThis represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[0-9a-z]+.victim.test2.xdi-attack.net\\000.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH1.victim.test2.xdi-attack.net\\000.test2.xdi-attack.net.',
 'name': 'inject-zero-direct-trigger-nodot',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'detail': 'Incorrect answer for attack query.\nThis does not mean an attack is possible, but it represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH1.victim.test2.xdi-attack.net.',
 'name': 'inject-zero-direct-verify-nodot',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'detail': 'Your resolver is vulnerable against a cache-poisoning attack using zero-byte mininterpretation.'
},
 {
'expected': [{
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[0-9a-z]+.victim.test2.xdi-attack.net.\\000.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH2.victim.test2.xdi-attack.net.\\000.test2.xdi-attack.net.',
 'name': 'inject-zero-direct-trigger-dot',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'detail': 'Incorrect answer for attack query.\nThis does not mean an attack is possible, but it represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH2.victim.test2.xdi-attack.net.',
 'name': 'inject-zero-direct-verify-nodot',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'detail': 'Your resolver is vulnerable against a cache-poisoning attack using zero-byte mininterpretation.'
},
 {
'expected': [{
'info': 'bad_cname',
 'type': 5,
 'testtype': 'critical',
 'data': '(?i)^[0-9a-z]+.victim.test2.xdi-attack.net.\\000.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[0-9a-z]+.victim.test2.xdi-attack.net.\\000.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH3.cnamezero.test2.xdi-attack.net',
 'name': 'inject-zero-cname-trigger-dot',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'detail': 'Incorrect answer for attack query.\nThis does not mean an attack is possible, but it represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH3.victim.test2.xdi-attack.net.',
 'name': 'inject-zero-cname-verify-dot',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'detail': 'Your resolver is vulnerable against a cache-poisoning attack using zero-byte mininterpretation.'
},
 {
'expected': [{
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[0-9a-z]+.victim\\\\.dot.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH1.victim\\.dot.test2.xdi-attack.net.',
 'name': 'inject-dot-direct-trigger',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'detail': 'Incorrect answer for attack query.\nThis does not mean an attack is possible, but it represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH1.victim.dot.test2.xdi-attack.net.',
 'name': 'inject-dot-direct-verify',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'detail': 'Your resolver is vulnerable against a cache-poisoning attack using dot-inside-label mininterpretation.'
},
 {
'expected': [{
'info': 'bad_cname',
 'type': 5,
 'testtype': 'critical',
 'data': '(?i)^[0-9a-z]+.victim\\\\.dot.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a_name',
 'type': 1,
 'testtype': 'critical',
 'name': '(?i)^[0-9a-z]+.victim\\\\.dot.test2.xdi-attack.net.$'
},
 {
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH2.cnamedot.test2.xdi-attack.net.',
 'name': 'inject-dot-cname-trigger',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'detail': 'Incorrect answer for attack query.\nThis does not mean an attack is possible, but it represents non-standard behaviour and could indicate\nthe use of a badly written resolver implementation.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^141.12.174.88$'
}],
 'type': 1,
 'qname': '$HASH2.victim.dot.test2.xdi-attack.net.',
 'name': 'inject-dot-cname-verify',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'detail': 'Your resolver is vulnerable against a cache-poisoning attack using dot-inside-label mininterpretation.'
},

{
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^5.45.109.212$'
}],
 'type': 1,
 'qname': 'fail01.dnssec.works.',
 'name': 'dnssec-noverify',
 'expected_result': False,
 'is_attack': False,
 'edns': False,
 'set_cd': False,
 'detail': "This resolver (or it's upstream) does not check DNSSEC,\ntherefore testing for attacks against DNSSEC is impossible."
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^134.91.78.139$'
}],
 'type': 1,
 'qname': 'sigfail.verteiltesysteme.net.',
 'name': 'cd-forward-trigger',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'set_cd': True,
 'detail': 'This resolver does not repect the CD (Checking disabled) bit.'
},
 {
'expected': [{
'info': 'bad_a',
 'type': 1,
 'testtype': 'critical',
 'data': '^134.91.78.139$'
}],
 'type': 1,
 'qname': 'sigfail.verteiltesysteme.net.',
 'name': 'cd-forward-verify',
 'expected_result': False,
 'is_attack': True,
 'edns': False,
 'set_cd': False,
 'detail': "This resolver is vulnerable against the CD forwarding attack,\nthereby allowing a malicious client to inject DNSSEC-unvalidated responses into it's cache.\nNOTE: This result is invalid if the resolver does not verify DNSSEC (see dnssec-noverify)."
},



 {
'expected': [{
'info': 'bad_a',
 'type': 16,
 'testtype': 'warning',
}],
 'type': 16,
 'class': 3,
 'qname': 'version.bind.',
 'name': 'version.bind',
 'expected_result': True,
 'is_attack': False,
 'edns': False,
 'hide': True,
 'detail': ''
}

]

TYPE_A     = 1
TYPE_CNAME = 5
TYPE_TXT   = 16
TYPE_SRV   = 33
TYPE_OPT   = 41

DEBUG      = False

def getplatform():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version()
    }

def ip2token(ipstr):
    return binascii.hexlify(ipaddress.ip_address(ipstr).packed).decode("ascii")

def log(txt):
    if DEBUG:
        print(txt)

def analyze(result):
    result["normal"] = True
    
    for key, test in result["results"].items():
        test["normal"] = (test["code"] == 0)
    
    if result["results"]["injectdot.bakeryfun.ml"]["answer"][1]["name"] != "test\\.123.injectdot1.injectdot.bakeryfun.ml.":
        result["results"]["injectdot.bakeryfun.ml"]["normal"] &= False

    for key, test in result["results"].items():
        result["normal"] &= test["normal"]

def qdtolist(rr):
    l = []
    while rr != None and type(rr) != scapy.packet.NoPayload:
        
        l.append({
            "name":  rr.qname.decode("ascii", "ignore"),
            "class": rr.qclass,
            "type":  rr.qtype
            
        })
        rr = rr.payload
    
    return l

def rrtoseq(rr):
    l = []
    while rr != None and type(rr) != scapy.packet.NoPayload:
        
        l.append(rr)
        rr = rr.payload
    
    return l

def rrtolist(rr):
    l = []
    while rr != None and type(rr) != scapy.packet.NoPayload:
        
        data = None
        
        if rr.type == TYPE_A:
            data = rr.rdata
            
        elif rr.type == TYPE_CNAME:
            data = rr.rdata.decode("ascii", "ignore")
            
        elif rr.type == TYPE_SRV:
            data = rr.target.decode("ascii", "ignore")
            
        elif rr.type == TYPE_TXT:
            data = b''.join(rr.rdata).decode("ascii", "ignore")
            
        #elif type(rr.rdata) == type(b""):
        #    data = binascii.hexlify(rr.rdata).decode("ascii")
        
        if rr.type != TYPE_OPT:
            l.append({
                "name":   rr.rrname.decode("ascii", "ignore"),
                "class":  rr.rclass,
                "type":   rr.type,
                "ttl":    rr.ttl,
                "data":   data
                
            })
        
        rr = rr.payload
    
    return l

class Scan:
    
    def __init__(self, questions, addr, mysocket, mp, targetname, output):
        
        self.output      = output
        self.mp          = mp
        self.remote      = addr # (addr, 53)
        self.targetname  = targetname
        self.socket      = mysocket
        self.tcp_socket  = None
        self.results     = {}
        
        self.questions   = questions
        
        self.nextid       = 0
        self.created      = time.time()
        self.lastseen     = time.time()
        self.lastsent     = time.time()
        self.tcp_question = None
        
        self.maxtries    = 2
        self.tries       = self.maxtries
        
        #self.myhash      = ip2token(self.remote[0])
        self.myhash      = hex(random.randint(0,0xffffffff) % 0xffffffff)[2:]
        
        self.exceptions  = []
        
        self.stats       = {
            "recv": 0,
            "sent": 0,
        }
        
    def getdata(self):
        return {
            "target": self.remote[0],
            "name": self.targetname,
            "results": self.results,
            "exceptions": self.exceptions,
            "stats": self.stats,
            "platform": getplatform()
        }
    
    def getqname(self, question):
        return question["qname"].replace("$HASH", self.myhash)
    
    def makequery(self, currentquestion):
            
        qid = self.questions.index(currentquestion)
        qname = self.getqname(currentquestion)
        
        # pkt = DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=currentquestion["type"], qclass=qclass)).build()
        
        if currentquestion["edns"]:
            ar = DNSRROPT()
        else:
            ar = None
        
        cd = False
        if "set_cd" in currentquestion and currentquestion["set_cd"]:
            cd = True
        
        pkt = DNS(id=qid, rd=1, cd=cd, qd=DNSQR(qname=qname, qtype=currentquestion["type"], qclass=currentquestion["class"]), ar=ar).build()
        
        return pkt
    
    def retry_tcp(self, currentquestion):
        self.tcp_question = currentquestion
        return self.connect_tcp()
    
    def connect_tcp(self):
        
        assert self.tcp_socket == None
        self.tcp_socket = self.mp.make_tcp_socket(self)
        
        self.tcp_socket.setblocking(False)
        
        # log("Connecting via TCP to " + self.remote[0])
        
        err  = self.tcp_socket.connect_ex(self.remote)
        
        return True
    
    def query_tcp(self, currentquestion):
        
        log("Testing " + currentquestion["name"] + " ... (tries = " + str(self.tries) + ", mode TCP)")
        
        assert self.tcp_socket != None
        self.tcp_socket.setblocking(False)
        
        pkt = self.makequery(currentquestion)
        pkt = struct.pack("!H", len(pkt)) + pkt
        
        self.lastsent = time.time()
        self.lastseen = time.time()
        
        self.stats["sent"] += 1
        
        self.tcp_socket.sendall(pkt)
        self.tcp_socket.shutdown(socket.SHUT_WR)
        
        return True
    
    def teardown_tcp(self):
        try:
            self.tcp_socket.close()
            self.mp.delete_tcp_socket(self.tcp_socket)
        except Exception as e:
            ex = traceback.format_exc()
            # log(ex)
            self.exceptions.append(ex)
            
        self.tcp_socket = None
        self.tcp_question = None
    
    def tcp_can_write(self):
        
        try:
            if self.tcp_question != None:
                self.query_tcp(self.tcp_question)
                self.tcp_question = None
        
        except Exception as e:
            ex = traceback.format_exc()
            # log(ex)
            self.exceptions.append(ex)
            self.teardown_tcp()
            return self.next()
        
    def tcp_can_read(self):
        
        try:
            
            self.tcp_socket.settimeout(1.0)
            
            pktlen = self.tcp_socket.recv(2)
            pktlen = struct.unpack("!H", pktlen)[0]
            
            # log("Reading " + str(pktlen) + " bytes from tcp socket")
            
            pkt = self.tcp_socket.recv(pktlen)
            
            self.tcp_socket.settimeout(0)
            
            self.teardown_tcp()
            self.recv(pkt, tcp=True)
        
        except Exception as e:
            ex = traceback.format_exc()
            self.exceptions.append(ex)
            self.teardown_tcp()
            return self.next()
            
        
    def tcp_exeption(self):
        # log("Got tcp exception")
        self.teardown_tcp()
        return self.next()
    
    def query_udp(self, currentquestion):
        
        log("Testing " + currentquestion["name"] + " ... (tries = " + str(self.tries) + ", mode UDP)")
        
        pkt = self.makequery(currentquestion)
        
        self.lastsent = time.time()
        self.lastseen = time.time()
        
        self.socket.sendto(pkt, self.remote)
        
        self.stats["sent"] += 1
        
        self.tries  -= 1
        self.nextid += 1
        
        return True
        
    def start(self):
        return self.next()
        
    def timeout(self):
        
        if self.tcp_socket != None:
            
            # log("Timeout during tcp operation, closing socket")
            self.teardown_tcp()
        
        return self.next()
        
    def next(self):
   
        # Give up if we never got an answer and have no tries left
        if len(self.results) <= 1 and self.tries == 0:
            log("Giving up becasue of no tries and no answers yet")
            return False
        
        # Check if we got an answer to the last question. If not, retry if there are tries left
        if self.nextid > 0:
            lastid = self.nextid - 1
            lastquestion = self.questions[lastid]
        
            if not(lastquestion["name"] in self.results) and self.tries > 0:
                
                log("Last test " + lastquestion["name"] + " has no answer, retryiing (tries = " + str(self.tries) + ")")
                self.nextid -= 1
            else:
                self.tries = self.maxtries
        
        # Check if there are questions to ask left
        if self.nextid >= len(self.questions):
            return False
        
        currentquestion = self.questions[self.nextid]
        self.query_udp(currentquestion)

        return True
    
    def dns_to_dict(self, dns):
        
        additional = rrtoseq(dns.ar)
        options    = None
        if len(additional) > 0:
            optrr = additional[-1]
            if optrr.type == TYPE_OPT:
                options = {
                    "dnssec": bool(optrr.z),
                    "udpsize": optrr.rclass,
                    "cookie": False,
                    "clientsubnet": None
                }
                
                for opt in optrr.rdata:
                    
                    if opt.optcode == 8: # CLIENT SUBNET
                        family, source_prefix_len, scope_prefix_len = struct.unpack("!HBB", opt.optdata[:4])
                        
                        address = ""
                        
                        if family == 1: # IPv4
                            address = opt.optdata[4:] + b"\x00\x00\x00\x00"
                            address = address[:4]
                            address = socket.inet_ntop(socket.AF_INET, address)
                            
                        if family == 2: # IPv6
                            address = opt.optdata[4:] + (b"\x00" * 16)
                            address = address[:16]
                            address = socket.inet_ntop(socket.AF_INET6, address)
                        
                        options["clientsubnet"] = {
                            "address": address,
                            "prefixlen": source_prefix_len
                        }
                    
                    if opt.optcode == 10: # COOKIE
                        options["cookie"] = True
                        
        
        js = {
            "flags":       {"aa": bool(dns.aa), "tc": bool(dns.tc), "rd": bool(dns.rd), "ra": bool(dns.ra), "z": bool(dns.z), "ad": bool(dns.ad), "cd": bool(dns.cd)},
            "code":        dns.rcode,
            "question":    qdtolist(dns.qd),
            "answer":      rrtolist(dns.an),
            "authorative": rrtolist(dns.ns),
            "additional":  rrtolist(dns.ar),
            "options":     options
        }
        
        return js
        
    def recv(self, pkt, tcp=False):
        
        tries = self.maxtries - self.tries
        self.stats["recv"] += 1
        
        now           = time.time()
        latency       = now - self.lastsent
        
        try:
            
            truncated = False
            
            nsquery  = None
            nsremote = None
            nstime   = None
            
            try:
                dns = DNS(pkt)
                
                currentquestion = self.questions[dns.id]
                
                truncated |= bool(dns.tc)
                
                # redis
                    
                if self.mp.use_redis:
                    
                    qname_full = self.getqname(currentquestion).lower()
                    if qname_full[-1] != ".":
                        qname_full = qname_full + "."
                        
                    # only do redis-lookup if query name is randomized, else we cannot
                    # identify the correct query
                    if "$HASH" in currentquestion["qname"]:
                        redis_id = "fragserv:" + qname_full + ":" + str(currentquestion["type"])
                        redis_query = self.mp.redis.get(redis_id)
                        
                        if redis_query:
                            redis_query    = redis_query.split(b",")
                            ns_recv_from   = redis_query[0].decode("ascii")
                            ns_recv_port   = int(redis_query[1].decode("ascii"))
                            nstime         = float(redis_query[2].decode("ascii"))
                            ns_recv_pkt    = binascii.unhexlify(redis_query[3])
                            ns_recv_pkt    = DNS(ns_recv_pkt)
                            
                            nsremote       = {"addr": ns_recv_from, "port": ns_recv_port}
                            nsquery        = self.dns_to_dict(ns_recv_pkt)
                        
                    # end redis
                
                js = {
                    "response":    self.dns_to_dict(dns),
                    
                    "nsquery":     nsquery,
                    "nsremote":    nsremote,
                    "nstime":      nstime,
                    
                    "latency":     latency,
                    "sent":        self.lastsent,
                    "received":    now,
                    "tries":       tries,
                    "tcp":         tcp
                    
                }
                
                # log("Got answer for " + currentquestion["name"] + ", id=" + str(dns.id))
                log(json.dumps(js, indent=2))
            
            except Exception as e:
                
                log(traceback.format_exc())
            
                self.exceptions.append(traceback.format_exc())

                probablytheid, flags = struct.unpack("!HH", pkt[:4])

                currentquestion = self.questions[probablytheid]
                
                js = {
                    "response":    None,
                    
                    "nsquery":     nsquery,
                    "nsremote":    nsremote,
                    "nstime":      nstime,
                    
                    "latency":     latency,
                    "sent":        self.lastsent,
                    "received":    now,
                    "tries":       tries,
                    "raw":         binascii.hexlify(pkt).decode("ascii"),
                    "tcp":         tcp
                }
                
                # Always assume a truncated response ...
                truncated = True
                
                # log("Got answer for " + currentquestion["name"] + " but cannot parse, id=" + str(probablytheid))
                # log(json.dumps(js, indent=2))
            
            self.output.progress_test(self.remote[0], currentquestion, js)
            
            log("Saving " + currentquestion["name"] + " tcp=" + str(tcp) + " tc=" + str(truncated))
            self.results[currentquestion["name"]] = js
            
            self.lastseen = now
            self.tries    = self.maxtries
            
            if truncated and not(tcp):
                return self.retry_tcp(currentquestion)
            else:
                return self.next()
        
        except Exception as e:
            ex = traceback.format_exc()
            log(ex)
            self.exceptions.append(ex)
            return self.next()
        
class Multiplexer:
    
    def __init__(self, nexttarget, tests, maxscanners, nb_total_tests, outputmodule, use_redis):
        
        self.redis_host = None 
        self.redis_port = None 
        
        self.use_redis   = use_redis
        self.nexttarget  = nexttarget
        self.sock        = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.scanners    = {}
        self.maxscanners = maxscanners
        
        self.nb_tests_done    = 0
        self.nb_total_targets = nb_total_tests
        
        if self.use_redis:
            print("Connecting to redis at " + self.redis_host + ":" + str(self.redis_port) + " ... ")
            
            try:
            
                self.redis = Redis(host=redis_host, port=redis_port, socket_timeout=10, socket_connect_timeout=10)
                self.redis.ping()
        
                print("Connected")
                
            except:
        
                print("Connection error")
                
                self.use_redis = False
        
        # { "info": "changes_case",      "type": TYPE_CNAME, "data": "^injectzero1\\.bakeryfun\\.ml\u0000\\.bakeryfun\\.ml\\.$",     "testtype": "warning"}
        
        self.tests = tests
            
        self.testdict = {}
        self.tcp_sockets = {}
            
        self.output = outputmodule
        
        for question in self.tests:
            
            if not("qname" in question):
                question["qname"] = question["name"]
            
            question["qname"] = question["qname"].replace("\\000", "\x00")
            
            if not("type" in question):
                question["type"] = 1
                
            if not("class" in question):
                question["class"] = 1
        
    def delete_tcp_socket(self, tcp_socket):
        del self.tcp_sockets[tcp_socket]
        
    def make_tcp_socket(self, scanner):
        # log("Making TCP socket for scanner " + scanner.remote[0])
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sockets[tcp_socket] = scanner
        return tcp_socket
        
    def run(self):
        
        for test in self.tests:
            self.testdict[test["name"]] = test
            
        nexttarget, nexttargetname = self.nexttarget()
        
        self.sock.setblocking(False)
        
        targets_since_last_reset  = 0
        receives_since_last_reset = 0
        last_reset = time.time()
        
        while nexttarget != None or len(self.scanners) > 0:
            
            # wait some time to prevent busy loop
            time.sleep(0.05)
            
            while nexttarget != None and len(self.scanners) < self.maxscanners:
                
                nextscan = Scan(self.tests, nexttarget, self.sock, self, nexttargetname, self.output)
                
                self.output.progress_new_target(nexttarget)
                
                self.scanners[nexttarget] = nextscan
                
                if not(nextscan.start()):
                    self.finalize(nextscan)
                    targets_since_last_reset += 1
                    
                nexttarget, nexttargetname = self.nexttarget()
            
            waiting_tcp_sockets = list(self.tcp_sockets.keys())
            all_sockets = waiting_tcp_sockets + [self.sock]
            read_ready, write_ready, exp_ready = select.select(all_sockets, waiting_tcp_sockets, waiting_tcp_sockets, 10)
            
            for s in read_ready:
                if s != self.sock:
                    if s in self.tcp_sockets:
                        scanner = self.tcp_sockets[s]
                        scanner.tcp_can_read()
                        
                        receives_since_last_reset += 1
                
            for s in write_ready:
                if s != self.sock:
                    if s in self.tcp_sockets:
                        scanner = self.tcp_sockets[s]
                        scanner.tcp_can_write()
                
            for s in exp_ready:
                if s != self.sock:
                    if s in self.tcp_sockets:
                        scanner = self.tcp_sockets[s]
                        scanner.tcp_exeption()
                
            if self.sock in read_ready:
                while True:
                    try:
                        pkt, remote = self.sock.recvfrom(0xffff)
                        
                        receives_since_last_reset += 1
                        
                        if remote in self.scanners:
                            if not(self.scanners[remote].recv(pkt)):
                                self.finalize(self.scanners[remote])
                                targets_since_last_reset += 1
                    except:
                        break
            else:
                
                # look for timed out scanners here
                timeout = []
                kill    = []
                
                for target in self.scanners.keys():
                    scanner = self.scanners[target]
                    
                    if scanner.created + 180 < time.time():
                        kill.append(scanner)
                    
                    elif scanner.lastseen + 10 < time.time():
                        timeout.append(scanner)
                
                for scanner in kill:
                    self.finalize(scanner)
                    targets_since_last_reset += 1
                
                for scanner in timeout:
                    if not(scanner.timeout()):
                        self.finalize(scanner)
                        targets_since_last_reset += 1
            """
            now = time.time()
            if now >= last_reset + 30.0:
                
                cpu_percent  = psutil.cpu_percent()
                mem_percent  = psutil.virtual_memory().percent
                cur_parallel = len(self.scanners)
                
                if cpu_percent > 90 or mem_percent > 90:
                    self.maxscanners -= max(1, int(self.maxscanners * 0.1))
                    
                elif cpu_percent < 70 and mem_percent < 70 and cur_parallel == self.maxscanners:
                    self.maxscanners += max(1, int(self.maxscanners * 0.1))
                
                time_diff = now - last_reset
                receives_per_sec = receives_since_last_reset / time_diff
                targets_per_sec = targets_since_last_reset / time_diff
                
                targets_remaining = self.nb_total_targets - self.nb_tests_done
                
                print("receives_per_sec: " + str(receives_per_sec))
                print("targets_per_sec:  " + str(targets_per_sec))
                print("targets_done:     " + str( self.nb_tests_done))
                print("ETA:              " + str( round(targets_remaining / (targets_per_sec + 0.0000001)) ) + " sec")
                print("max_parallel:     " + str( self.maxscanners))
                print("cur_parallel:     " + str( cur_parallel))
                print("cpu_percent:      " + str( cpu_percent))
                print("mem_percent:      " + str( mem_percent))
                print("curr_active:      " + str(','.join(map(str, self.scanners.keys()))))
                
                sys.stderr.flush()
                
                last_reset = time.time()
                receives_since_last_reset = 0
                targets_since_last_reset  = 0
            """
                
    def end(self):
        self.output.end()
                
    def finalize(self, scan):
        del self.scanners[scan.remote]
        
        self.nb_tests_done += 1
        
        try:
            
            result = scan.getdata()
            self.output.putresult(scan.remote, result)
            
        except:
            log(traceback.format_exc())

class OutputModule:
    
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    WHITE  = "\033[1;37m"
    YELLOW = "\033[0;33m"
    NORMAL = "\033[0m"
    
    def __init__(self, opt):
        pass
    
    def progress_new_target(self, target):
        print("Started scanning " + str(target))
        pass
    
    def progress_test(self, target, test, result):
        try:
            
            if "hide" in test and test["hide"]:
                return
            
            result = rate(test, result)     
            is_expected_result = test["expected_result"] == result["rating"]["ok"]
            is_attack = test["is_attack"]
            
            color = ""
            
            if is_attack:
                if result["rating"]["ok"]:
                    vuln  = "vulnerable"
                    color = OutputModule.RED
                else:
                    vuln  = "invulnerable"
                    color = OutputModule.GREEN
            else:
                vuln = "positive" if result["rating"]["ok"] else "negative"
                if not(is_expected_result):
                    color = OutputModule.YELLOW
                    
            logtag = " EXPECTED " if is_expected_result else "UNEXPECTED"
            indent = "              "
            
            info = indent+test["detail"].replace("\n", "\n"+indent) if "detail" in test else ""
            
            failedexp = result["rating"]["failed_expectations"]
            for exc in failedexp:
                test_exc  = list(filter(lambda test_exc: test_exc["info"] == exc, test["expected"]))
                
                if len(test_exc) == 0:
                    info += "\n" + indent + exc
                    
                else:
                    test_exc  = test_exc[0]
                    test_type = "name" if "name" in test_exc else "data"
                    
                    # info = test_exc["info"]
                    
                    if test_type == "name":
                        for name in map(lambda answer: answer["name"], result["response"]["answer"]):
                            info += "\n" + indent + " - " + exc + ": " + name + " != " + test_exc["name"]
                    
                    if test_type == "data":
                        for data in map(lambda answer: answer["data"], result["response"]["answer"]):
                            info += "\n" + indent + " - " + exc + ": " + data + " != " + test_exc["data"]
            
            if is_expected_result:
                print(color + " [" + logtag + "] " + test["name"] + " " + vuln + OutputModule.NORMAL)
            else:
                print(color + " [" + logtag + "] " + test["name"] + " " + vuln + "\n" + info + OutputModule.NORMAL)
                # print(result)
            
            
        except:
            traceback.print_exc()
        pass
    
    def putresult(self, target, result):
        try:
            print("Finished scanning " + str(target))
            
            result = preprocess(result)
            
            # print(result)
            
            if result["characteristics"]["version"]:
                print("Resolver at " + str(target) + " has version " + result["characteristics"]["version"])
            if result["characteristics"]["version_match"]:
                print("Resolver at " + str(target) + " classified as " + result["characteristics"]["version_match"])
            
            remote_addrs = set()
            client_addrs = set()
            latencies = []
            
            for test in result["results"]:
                if result["results"][test]["nsremote"] != None:
                    remote_addrs.add(result["results"][test]["nsremote"]["addr"])
                    
                if result["results"][test]["nsquery"] != None:
                    if result["results"][test]["nsquery"]["options"] != None and "clientsubnet" in result["results"][test]["nsquery"]["options"] and result["results"][test]["nsquery"]["options"]["clientsubnet"] != None:
                        clientsubnet = result["results"][test]["nsquery"]["options"]["clientsubnet"]
                        client_addrs.add(clientsubnet["address"] + "/" + str(clientsubnet["prefixlen"]))
                    
                latencies.append(result["results"][test]["latency"])
            
            # print("Resolver at " + str(target) + " queries arrive at the nameserver from " + str(remote_addrs))
            # if len(client_addrs) > 0:
            #     print("Resolver at " + str(target) + " indicates clientsubnets " + str(client_addrs))
            # print("Resolver at " + str(target) + " has avg latency " + str(round(1000 * statistics.mean(latencies), 1)) + " ms")
            #print(json.dumps(result, indent=2))
        except:
            traceback.print_exc()
        pass
        
    def end(self):
        pass

class FileOutputModule(OutputModule):
    
    def __init__(self, filename="results.json"):
        # print("Writing results to " + filename)
        
        if filename.endswith(".gz"):
            self.fp = gzip.open(filename, "wb")
        else:
            self.fp = open(filename, "wb")
        
    def progress_new_target(self, target):
        pass
    
    def progress_test(self, target, test, result):
        pass
    
    def putresult(self, target, result):
        self.fp.write(json.dumps(result).encode("ascii") + b"\n")
        self.fp.flush()
        
    def end(self):
        self.fp.close()

class MultiOutputModule(OutputModule):
    
    def __init__(self, outputs):
        self.outputs = outputs
        
    def progress_new_target(self, target):
        for output in self.outputs:
            output.progress_new_target(target)
    
    def progress_test(self, target, test, result):
        for output in self.outputs:
            output.progress_test(target, test, result)
    
    def putresult(self, target, result):
        for output in self.outputs:
            output.putresult(target, result)
        
    def end(self):
        for output in self.outputs:
            output.end()

class UploadOutputModule(OutputModule):
    
    def __init__(self, url):
        self.url = url
        
    def progress_new_target(self, target):
        pass
    
    def progress_test(self, target, test, result):
        pass
    
    def putresult(self, target, result):
        try:
            x = requests.post(self.url, json=result, headers={'User-Agent': TOOL_NAME})
        except:
            pass
        
    def end(self):
        pass

CTR = 0
GLOABL_TARGET = None
def next_argv():
    global CTR, GLOABL_TARGET
    
    if CTR == 0:
        CTR = 1
        return (GLOABL_TARGET, args.port), GLOABL_TARGET
    else:
        return None, None

def next_file():
    global targetfile
    line = targetfile.readline().strip().decode("ascii")
    if line != "":
        line = line.split(maxsplit=1)
        if len(line) == 1:
            return (line[0], 53), line[0]
        else:
            return (line[0], 53), line[1]
    else:
        return None, None

parser = argparse.ArgumentParser(description='Scan DNS resolvers.')

parser.add_argument('resolver', nargs='?', help='A single resolver to test')
parser.add_argument('-d', '--debug', action='store_true', help="enable debug logging")
parser.add_argument('-P', '--port', type=int, help="resolver port", default=53)

args = parser.parse_args()
wait = False

if args.debug:
    DEBUG = True

elif args.resolver != None:
    GLOABL_TARGET = args.resolver
    next_func = next_argv
    total_tests = 1
else:
    import dns.resolver
    GLOABL_TARGET = dns.resolver.Resolver().nameservers[0]
    next_func = next_argv
    total_tests = 1
    wait = True

print("")
print(TOOL_NAME)
print("--------------------------------------------------------------")
print("DISCLAIMER: The results of this tool are collected anonymously")
print("in order to improve collect more inforamtion about vulnerable")
print("systems and networks and to improve the security of DNS")
print("infrastructure in the Internet.")
print("")
print("If you do not agree with this data collection, you can still test")
print("your DNS resolver manually, we provide instructions on how to conduct")
print("such a manual test as https://xdi-attack.net/test.html")
print("")
print("NOTE: The test results of this tool might become invalid")
print("when re-running the tool because of caching.")
print("Please wait at least 60 seconds before re-running the tool.")
print("")
print("Press [Enter] to continue or [CTRL+C] to exit")
print("")
sys.stdin.readline()

TESTOUTPUT_FILE = "testresult.json"

tests = DEFAULT_TESTS    
mp    = Multiplexer(next_func, tests, 1, total_tests, MultiOutputModule([OutputModule(""), UploadOutputModule("https://xdi-attack.net/resultcallback_tool.php"), FileOutputModule(TESTOUTPUT_FILE)]), False)

"we collect anonymised information about the users of our tool, in order to improve the security of DNS infrastructure in the Internet."

try:
    mp.run()
finally:
    mp.end()

print("")
print("Test result written to " + TESTOUTPUT_FILE)

if wait:
    print("")
    print("Press [Enter] to exit")
    sys.stdin.readline()

