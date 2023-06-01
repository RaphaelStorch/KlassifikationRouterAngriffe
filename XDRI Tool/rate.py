import re

LOOKUP_IPDB = False
MYIPDB      = None

TEST_VERSION    = "version.bind"
TEST_MYRESOLVER = "myresolver"

RESOLVER_FINGERPRINTS = [
                                                          # max 8 chars!
    
    ("(?i)^(bind)|(9\\.[0-9]+\\.[0-9]+)",                 "bind"),
    ("(?i)^dnsmasq",                                      "dnsmasq"),
    ("(?i)^unbound",                                      "unbound"),
    ("(?i)^Microsoft DNS",                                "microsoft"),
    ("(?i)PowerDNS",                                      "powerdns"),
    ("(?i)^Version: [a-z0-9-]+/",                         "answerX"),
    ("(?i)^nominum Vantio",                               "nominum"),
    ("(?i)^ZyWALL DNS",                                   "zywall"),
]

def rate(test, result):
  
    name = test["name"]
    failed_expectations = []
    warnings = []
    
    if not("response") in result or result["response"] == None:
        allmatch = False
        failed_expectations.append("noresponse")
    else:
        response = result["response"]
        
        allmatch  = True
        
        if response["code"] != 0:
            allmatch = False
            failed_expectations.append("code_" + str(response["code"]))
        
        for expectation in test["expected"]:
            
            expectationmatch = False
            
            for record in response["answer"]:
                
                recordmatch = True
                
                if "type" in expectation:
                    recordmatch &= expectation["type"] == record["type"]
                    
                if "data" in expectation:
                    if record["data"] != None:
                        recordmatch &= re.match(expectation["data"], record["data"]) != None
                    else:
                        recordmatch &= False
                    
                if "name" in expectation:
                    recordmatch &= re.match(expectation["name"], record["name"]) != None
                
                if recordmatch:
                    expectationmatch = True
                
            if not(expectationmatch) and expectation["testtype"] == "critical":
                allmatch = False
                failed_expectations.append(expectation["info"])
                
            if not(expectationmatch) and expectation["testtype"] == "warning":
                warnings.append(expectation["info"])
        
        if "required" in test:
            required_test_name   = test["required"]
            required_test_result = results[required_test_name]
            
            if not(required_test_result["ok"]):
                allmatch = None
                failed_expectations.append("required_test_failed")
    
    result["rating"] = {
        "ok": allmatch,
        "failed_expectations": failed_expectations,
        "warnings": warnings
    }
    
    return result

def preprocess(sample):
    global LOOKUP_IPDB, MYIPDB, RESOLVER_FINGERPRINTS, TEST_VERSION, TEST_VERSION
    
    results         = sample["results"]
    characteristics = {}
    
    sample["characteristics"] = characteristics
    
    ns_query_ips       = set()
    ns_query_asn       = set()
    ns_query_countries = set()
    
    # Get geolocation and ASN of target
    if LOOKUP_IPDB:
        characteristics["target_geo"] = MYIPDB.find(sample["target"])
        
        for result in results.values():
            
            if not("nsremote" in result):
                continue
            
            if result["nsremote"] != None:

                geo = MYIPDB.find(result["nsremote"]["addr"])
                result["nsremote"]["geo"] = geo
                
                ns_query_ips.add(result["nsremote"]["addr"])
                
                if geo:
                    ns_query_asn.add(geo["asn"])
                    ns_query_countries.add(geo["country"])
            
            if result["nsquery"] != None and result["nsquery"]["options"] != None and "clientsubnet" in result["nsquery"]["options"] and result["nsquery"]["options"]["clientsubnet"] != None:
                
                ip = result["nsquery"]["options"]["clientsubnet"]["address"]
                result["nsquery"]["options"]["clientsubnet"]["geo"] = MYIPDB.find(ip)
        
    else:
        characteristics["target_geo"] = None
        
        for result in results.values():
            
            if not("nsremote" in result):
                continue
            
            if result["nsremote"] != None:
                result["nsremote"]["geo"] = None
                
    characteristics["nsquery"] = {
        "ips":       list(ns_query_ips),
        "asn":       list(ns_query_asn),
        "countries": list(ns_query_countries),
    }
    
    # Get geolocation and ASN of upstream resolver - disabled and replaced by nsquery
    #if TEST_MYRESOLVER in results and "answer" in results[TEST_MYRESOLVER]["response"] and len(results[TEST_MYRESOLVER]["response"]["answer"]) > 0:
    #    resolver_ip = results[TEST_MYRESOLVER]["response"]["answer"][0]["data"]
    #    characteristics["resolver_ip"]  = resolver_ip
    #    if LOOKUP_IPDB:
    #        characteristics["resolver_geo"] = MYIPDB.find(resolver_ip)
    #    else:
    #        characteristics["resolver_geo"] = None
    #else:
    characteristics["resolver_ip"]  = None
    characteristics["resolver_geo"] = None
    
    # Classify target by version.bind
    if TEST_VERSION in results and "response" in results[TEST_VERSION] and results[TEST_VERSION]["response"] != None and len(results[TEST_VERSION]["response"]["answer"]) > 0:
        version = results[TEST_VERSION]["response"]["answer"][0]["data"]
        characteristics["version"]      = version
        
        version_match = None
        for fp in RESOLVER_FINGERPRINTS:
            if re.match(fp[0], str(version)) != None:
                version_match = fp[1]
                break
        characteristics["version_match"] = version_match
            
    else:
        characteristics["version"]       = None
        characteristics["version_match"] = None
    
    return sample
