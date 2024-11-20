import urllib.parse  # Corrected import for URL parsing
import http.client  # Corrected import for HTTP client
import xml.etree.ElementTree as ET  # Corrected import for XML parsing
import base64
import csv

log_path = 'burp_crawl.log'
output_csv_log = 'httplog.csv'  # Use as a string filename
class_flag = "l"

class LogParse:
    def __init__(self):
        pass

    def parse_log(self, log_path):
        '''
        This function accepts a Burp log file path
        and returns a dictionary of requests and responses.
        Example: result = {'GET /page.php...':'200 OK HTTP /1.1....'}
        '''
        result = {}
        try:
            with open(log_path) as file:
                pass  # Check if the log file exists and is accessible
        except IOError:
            print(f"[+] Error!!! {log_path} doesn't exist.")
            exit()
        
        try:
            # Parse the XML file
            tree = ET.parse(log_path)
        except Exception as e:
            print("[+] Oops! Please ensure no binary data (e.g., raw image or .swf files) is in the log.")
            print("Error details:", e)
            exit()
        
        # Extract root element
        root = tree.getroot()
        for reqs in root.findall('item'):
            # Find request and response tags and process their text content
            raw_req = reqs.find('request').text
            raw_resp = reqs.find('response').text
            
            # Ensure text fields are not None and decode URL encoding
            if raw_req:
                raw_req = urllib.parse.unquote(raw_req)
            
            # Add request-response pair to result dictionary
            result[raw_req] = raw_resp if raw_resp else ""
        
        return result

    def parseRawHTTPReq(self, rawreq):
        if isinstance(rawreq, bytes):
            try:
                raw = rawreq.decode('utf-8')  
            except UnicodeDecodeError:
                raw = rawreq.decode('latin1')  # Use as-is if decoding fails
        else:
            raw=rawreq        

        headers = {}
        body = ""
        
        # Split headers and body
        sp = raw.split("\r\n\r\n", 1)
        head = sp[0]
        if len(sp) > 1:
            body = sp[1]
        
        # Parse method and path from the first line
        cl = head.split('\n')
        method = cl[0].split(' ', 2)[0]
        path = cl[0].split(' ', 2)[1]
        
        # Parse headers
        for line in cl[1:]:
            slicel = line.split(': ', 1)
            if len(slicel) == 2:
                headers[slicel[0]] = slicel[1]

        return headers, method, body, path

# Define bad words for feature extraction
badwords = ['sleep', 'drop', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by']

def ExtractFeatures(headers, method, path, body):
    '''
    Extract features from HTTP request for analysis.
    '''
    badwords_count = 0
    # Decode URL-encoded strings
    path_decoded = urllib.parse.unquote_plus(path)
    body_decoded = urllib.parse.unquote(body)

    # Count various features
    single_q = path_decoded.count("'") + body_decoded.count("'")
    double_q = path_decoded.count("\"") + body_decoded.count("\"")
    dashes = path_decoded.count("--") + body_decoded.count("--")
    braces = path_decoded.count("(") + body_decoded.count("(")
    spaces = path_decoded.count(" ") + body_decoded.count(" ")

    # Count bad words in path, body, and headers
    for word in badwords:
        badwords_count += path_decoded.lower().count(word) + body_decoded.lower().count(word)
        for header_value in headers.values():
            badwords_count += header_value.lower().count(word)

    # Return features as a list
    return [
        method,
        path_decoded.strip(),
        body_decoded.strip(),
        single_q,
        double_q,
        dashes,
        braces,
        spaces,
        badwords_count,
        class_flag
    ]

# Initialize the CSV file with headers
with open(output_csv_log, "w", newline='', encoding='utf-8') as f:
    c = csv.writer(f)
    c.writerow([
        "method", "path", "body",
        "single_q", "double_q", "dashes",
        "braces", "spaces", "badwords_count", "class"
    ])

# Create an instance of LogParse and parse the log
lp = LogParse()
result = lp.parse_log(log_path)

# Append parsed data to the CSV file
with open(output_csv_log, "a", newline='', encoding='utf-8') as f:
    c = csv.writer(f)
    for raw_req, raw_resp in result.items():
        # Decode request if base64 encoded
        try:
            raw = base64.b64decode(raw_req)
        except (base64.binascii.Error, TypeError):
            raw = raw_req  # Use raw request if decoding fails

        # Parse the raw HTTP request
        headers, method, body, path = lp.parseRawHTTPReq(raw)

        # Extract features
        feature_data = ExtractFeatures(headers, method, path, body)

        # Write row to CSV
        try:
            c.writerow(feature_data)
        except UnicodeEncodeError as e:
            print(f"[+] UnicodeEncodeError: {e}")
            # Optionally, you can handle or log this error further
            continue