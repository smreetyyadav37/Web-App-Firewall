from xml.etree import ElementTree as ET
import http.client
import urllib.parse
from difflib import SequenceMatcher
import string
import random
import argparse
import html
import glob
import importlib
from io import StringIO
import gzip

part1 = '''<!DOCTYPE html><html><head><meta charset="utf-8" /><title>Burpy Version - 0.1 Test Report</title><link href="http://www.w3resource.com/twitter-bootstrap/twitter-bootstrap-v2/docs/assets/css/bootstrap.css" rel="stylesheet" type="text/css" /></head><body><div class="well span12 offset1"><h1>Burpy v0.1 Report</h1></br><p><b>Author </b>: <a href="http://www.debasish.in/">Debasish Mandal</a></p><p><b>Total Number of Request(s) Tested </b>: {number}</br><b>Scan Scope : </b>{target}</br></div><div class="well span12 offset1"><div class="container-fluid"><div class="accordion" id="accordion2"></div>'''
part2 = '''<div class="accordion-group"><div class="accordion-heading"><a class="accordion-toggle" data-toggle="collapse" data-parent="#accordion2" href="#{col_id}">{title}</a></div><div id="{col_id}" class="accordion-body collapse" style="height: 0px; "><div class="accordion-inner">{response}</div></div></div>'''
part3 = '''</div></div></div><script type="text/javascript" src="http://www.w3resource.com/twitter-bootstrap/twitter-bootstrap-v2/docs/assets/js/jquery.js"></script><script type="text/javascript" src="http://www.w3resource.com/twitter-bootstrap/twitter-bootstrap-v2/docs/assets/js/bootstrap-collapse.js"></script></body></html>'''

class Core:
    def banner(self):
        print('''
                ____                                       ___  __ 
               |  _ \\                                     / _ \\_|
               | |_) |_   _ _ __ _ __  _   _   ______  __ | | | || |
               |  _ <| | | | '__| '_ \\| | | | |______| \\ \\/ / | | || |
               | |_) | |_| | |  | |_) | |_| |           \\ V /  | |_| || |
               |____/ \\__,_|_|  | .__/ \\__, |            \\_/    \\___(_)_|
                            | |     __/ |                            
                            |_|    |___/       
        ''')
        print('Burpy v0.1 Portable and Flexible Web Application Security Scanner')
        print('Author : Debasish Mandal (http://www.debasish.in)')

    def cmd_option(self):
        global target_domain, burp_suite_log, ssl
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', type=str, required=True, help='Target/Scan Scope domain')
        parser.add_argument('-l', type=str, required=True, help='Full path to burp suite log')
        parser.add_argument('-s', type=str, required=True, help='Use of SSL on or off')
        args = parser.parse_args()
        target_domain = args.t
        burp_suite_log = args.l
        ssl = args.s

    def id_generator(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def write_report(self, title, res_reason, res_code, base_request, crafted_request, res_head_dict, latest_response):
        latest_response = html.escape(latest_response)
        base_request = base_request.replace('\n', '</br>')
        crafted_request = crafted_request.replace('\n', '</br>')
        HOST = target_domain
        url = self.gerequestinfo(base_request, "path")
        path_u = url[:50] + "..." if len(url) > 50 else url
        raw_resp = "HTTP/1.1 " + str(res_reason) + " " + res_code + "</br>"
        for ele in res_head_dict:
            raw_resp += f"{ele}: {res_head_dict[ele]}</br>"
        raw_resp += "</br>" + latest_response
        raw = f"<b>Base Request</b></br>{base_request}</br></br><b>Crafted Request&nbsp;&nbsp;&nbsp;[{title[1]}]</b></br></br>{crafted_request}</br><b>Live Response</b></br>{raw_resp}"

        with open('Report.html', 'a') as report:
            final = part2.format(response=raw, col_id=self.id_generator(), title=f"<b>http(s)://{HOST}{path_u}</b>[{title[0]}]")
            report.write(final)

    def difference(self, cont1, cont2):
        return SequenceMatcher(None, cont1, cont2).ratio() * 100

    def parse_log(self, log_path):
        result = {}
        try:
            with open(log_path): pass
        except IOError:
            print(f"[+] Error!!! {log_path} doesn't exist..")
            exit()
        try:
            tree = ET.parse(log_path)
        except Exception:
            print('[+] Please ensure no binary data in Log, like raw image dumps, flash dumps, etc.')
            exit()
        root = tree.getroot()
        for reqs in root.findall('item'):
            raw_req = urllib.parse.unquote(reqs.find('request').text)
            raw_resp = reqs.find('response').text
            result[raw_req] = raw_resp
        return result

    def gerequestinfo(self, raw_stream, query):
        headers = {}
        sp = raw_stream.split('\n\n', 1)
        head, body = (sp[0], sp[1]) if len(sp) > 1 else (sp[0], "")
        c1 = head.split('\n', head.count('\n'))
        method, path = c1[0].split(' ', 2)[:2]
        if query == "path":
            return path
        for i in range(1, len(c1)):
            slice1 = c1[i].split(': ', 1)
            if slice1[0]:
                headers[slice1[0]] = slice1[1]
        return headers.get(query)

    def loadallmodules(self):
        avlbl_mods = {}
        mods = glob.glob("modules/*.py")
        for mod in mods:
            print(f'[+] \t\tLoaded... {mod}')
            try:
                modl = importlib.import_module(mod.replace('.py', '').replace('/', '.'))
                avlbl_mods[self.id_generator()] = modl.main
            except Exception as e:
                print(f'[+] Error!! Could not import {mod}')
        return avlbl_mods
