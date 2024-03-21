import sys
try:
    from rich.table import Table
    from rich.console import Console
    import re
    import json
    import argparse
except:
    print("Missing modules!")
    sys.exit(1)

def powershell_scanner(filetoinput):
    ps_indicators = json.load(open("ps_script_indicators.json"))
    fin = open(filetoinput, 'r')
    file = fin.read()
    for pattern in ps_indicators:
        patternT = Table(title="PowerShell Script Indicators extracted split by categories")
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
    powershell_scanner(filetoinput)