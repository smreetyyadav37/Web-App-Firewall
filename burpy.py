import core

def initiate(dict_req_resp):
    '''
    Script initiation - Writes the initial part of the report.
    '''
    print('[+] Found ' + str(len(dict_req_resp)) + " requests from provided Burp Log...")
    input('[+] Press Enter to start Test___')  # Changed raw_input to input for Python 3
    print('[+] Starting Test...')
    
    # Write the report header
    report_head = core.part1.replace('{number}', str(len(dict_req_resp))).replace('{target}', core.target_domain)
    with open('Report.html', 'w') as report:
        report.write(report_head)
    
    # Iterate through all request/response pairs
    for item in dict_req_resp:
        if base.gerequestinfo(item, "Host") == core.target_domain:  # Check if request is in the test scope
            for testcase in moduledict:  # Execute all module test cases
                result = moduledict[testcase](item, core.ssl)
                
                # If test result is positive, process and add it to the report
                if len(result) > 5:
                    print('[+] Test Result Positive')
                    base.write_report(result[0], result[2], result[3], item, result[1], result[4], result[5])
                else:
                    print('[+] Test Result Negative')
        else:
            print('[+] Skipping... Request not associated with', core.target_domain)
    
    print('[+] Test Completed... Report.html Generated')
    
    # Append closing HTML part to the report file
    with open('Report.html', 'a') as report:
        report.write(core.part3)

if __name__ == '__main__':
    base = core.Core()
    base.banner()
    base.cmd_option()
    
    # Parse the log and load modules
    result = base.parse_log(core.burp_suite_log)
    target = core.target_domain
    moduledict = base.loadallmodules()
    
    # Initiate the testing process
    initiate(result)
