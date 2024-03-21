import sys
try:
    from rich.table import Table
    from rich.console import Console
    import re
    import json
    import argparse
    import hashlib
except:
    print("Missing modules!")
    sys.exit(1)

def get_md5(filetoinput):
    fin = open(filetoinput, 'rb')
    data = fin.read()
    md5_results = hashlib.md5(data).hexdigest()
    print(f"[*] MD5 hash of the file is: {md5_results}\n")
    print(f"[*] Beginning PowerShell Analysis for {filetoinput}...\n\n")
    print("PowerShell Script Indicators extracted split by categories:")

def powershell_scanner(filetoinput):
    ps_indicators = json.load(open("ps_script_indicators.json"))
    fin = open(filetoinput, 'r')
    file = fin.read()
    for pattern in ps_indicators:
        patternT = Table()
        patternT.add_column(f"Suspicious indicators for {pattern}", justify="center")


        # iterating patterns now
        for code in ps_indicators[pattern]["script_IOCs"]:
            strings_extracted = file.replace('\n', '')
            matching_IOCs = re.findall(code, strings_extracted, re.IGNORECASE) # The .findall() method iterates over a string to find a subset of characters that match a specified pattern, returns list of every pattern match that occurs in a given string.
            # print(matching_IOCs)
            if matching_IOCs != []:
                patternT.add_row(code)
                ps_indicators[pattern]["counter"] += 1 # counter

        if ps_indicators[pattern]["counter"] != 0:
            console =  Console()
            console.print(patternT) 
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='PS_Analyzer_Module', description='PowerShell Analyzer', usage='%(prog)s -f file')
    parser.add_argument("-f", "--file", required=True, help="powershell file to analyze")
    args = parser.parse_args()
    filetoinput = args.file

    if not args.file:
        print('error: must specify -f file')
        sys.exit(1)
    
    art = r"""
__________                                 .__           .__  .__       _____                .__                              
\______   \______  _  __ ___________  _____|  |__   ____ |  | |  |     /  _  \   ____ _____  |  | ___.__.________ ___________ 
 |     ___/  _ \ \/ \/ // __ \_  __ \/  ___/  |  \_/ __ \|  | |  |    /  /_\  \ /    \\__  \ |  |<   |  |\___   // __ \_  __ \
 |    |  (  <_> )     /\  ___/|  | \/\___ \|   Y  \  ___/|  |_|  |__ /    |    \   |  \/ __ \|  |_\___  | /    /\  ___/|  | \/
 |____|   \____/ \/\_/  \___  >__|  /____  >___|  /\___  >____/____/ \____|__  /___|  (____  /____/ ____|/_____ \\___  >__|   
                            \/           \/     \/     \/                    \/     \/     \/     \/           \/    \/       
    BY Davincico
    """
    print(art)
    print("[*] Obtaining MD5 Hash of the file ...\n")
    get_md5(filetoinput)
    powershell_scanner(filetoinput)