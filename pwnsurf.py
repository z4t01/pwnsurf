#!/usr/local/bin/python
import requests
import json
import os
import sys
import time
import urllib3
import threading
import csv


def output(url,response):
    #filter output based on response code
    bad_codes = ["404","504","502"]
    status_code = response.status_code
    length = len(response.content)
    if str(status_code) not in bad_codes:
        print(url+"  ====>  "+str(response.status_code)+","+str(length)+" bytes.")  

def discovery(domain,writer):
    extensions = [".php",".jsp",".aspx"]
    pages = ["home","index","default","admin"]
    dirs = ["admin","administrator"]
    
    headers = {}
    '''headers = {
    'target_bugbounty_header': "application/json"
    }'''
    http_url = "http://"+domain+":80/"
    https_url = "https://"+domain+":443/"
    urls = [http_url,https_url]
    for url in urls:
        try:
            #pages
            for page in pages:
                for ext in extensions:
                    rurl = url+page+ext
                    response = requests.request("GET", rurl, headers=headers,verify=False)
                    len_index = len(response.content)
                    output(rurl,response)
                    #data: url,code,length
                    data = [rurl,str(response.status_code),str(len(response.content))]
                    writer.writerow(data)
                    time.sleep(1)
                    
            #dirs
            for dir in dirs:
                rurl = url+page+ext
                response = requests.request("GET", rurl, headers=headers,verify=False)
                output(rurl,response)
                data = [rurl,str(response.status_code),str(len(response.content))]
                writer.writerow(data)
                time.sleep(1)
            
        except Exception as e:
            #print(e)
            continue



def get_sub_domains(domain,writer,apikey):
    threads = []
    global outfile
    try:
      url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"
      querystring = {"children_only":"true"}
      headers = {
      'accept': "application/json",
      'apikey': apikey
      }
      response = requests.request("GET", url, headers=headers, params=querystring)
      result_json=json.loads(response.text)
      sub_domains=[i+'.'+domain for i in result_json['subdomains']]
      print("Discovered " + str(len(sub_domains)) + " subdomains.")
    except Exception:
        print("Security trails APIs error.Killing.")
        sys.exit(0)

    for domain in sub_domains:
        t = threading.Thread(target=discovery,args=(domain,writer))
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
    outfile.close()
    

        

apikey = open("key.txt").readline()
domain = sys.argv[1]
outfile = open(str(domain)+".csv","w",encoding='UTF8', newline='')
writer = csv.writer(outfile)
header = ['URL','Status Code','Len']
writer.writerow(header)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
get_sub_domains(domain,writer,apikey)