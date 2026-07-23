'''
   Copyright (c) 2026 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   calculator.py
   ---------------
   This plugin reads calculator history.
'''

import logging
import re
from decimal import Decimal
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *


__Plugin_Name = "CALCULATOR" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Calculator History"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads calculator history"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide the folder /Users/<USER>/Library/Containers/com.apple.calculator/Data/Library/Application Support/default.store as input'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class CalculatorHistoryInfo():
    def __init__(self, timestamp, expression, result, mode, user, source):
        self.timestamp = timestamp
        self.expression = expression
        self.result = result
        self.mode = mode
        self.user = user
        self.source = source

def PrintAll(calculator_histories, output_params):

    calculator_info = [ ('Timestamp',DataType.DATE),('Expression',DataType.TEXT),
                        ('Result',DataType.TEXT),('Mode',DataType.TEXT),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(calculator_histories)) + " calculator history item(s) found")
    calculator_list = []
    for calc in calculator_histories:
        if calc.mode == 'basic':
            exp = convert_exponential_numbers(calc.expression)
            res = convert_exponential_numbers(calc.result)
        else:
            exp = calc.expression
            res = calc.result
        calc_item =  [ calc.timestamp, exp, res, calc.mode,
                        calc.user, calc.source
                      ]
        calculator_list.append(calc_item)
    WriteList("calculator history", "CalculatorHistory", calculator_list, calculator_info, output_params, '')



def convert_exponential_numbers(text: str) -> str:
    # Match integers or decimals written in scientific notation (e.g., 5E-34, -1.2e+4)
    pattern = r'-?\d+(?:\.\d+)?[eE][+-]?\d+'
    
    def replace_with_normal(match):
        # Parse using Decimal to avoid floating-point math inaccuracies
        raw_number = match.group(0)
        decimal_value = Decimal(raw_number)
        
        # Force a maximum of 8 decimal places
        formatted = f"{decimal_value:.8f}"
        
        # Clean up any unnecessary trailing zeros (e.g., 0.50000000 -> 0.5)
        if '.' in formatted:
            formatted = formatted.rstrip('0').rstrip('.')
            if formatted == "-0" or formatted == "":
                formatted = "0"
                
        return formatted

    # Search the string and replace all matches dynamically
    return re.sub(pattern, replace_with_normal, text)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ExtractAndReadDb(mac_info, calculator_histories, user, file_path, parser_function):
    mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
    db, wrapper = OpenDbFromImage(mac_info, file_path)
    if db:
        parser_function(calculator_histories, db, user, file_path)
        db.close()

def OpenLocalDbAndRead(calculator_histories, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(calculator_histories, conn, '', file_path)
        conn.close()

def process_calculator_db(calculator_histories, db, user, file_path):
    query = """SELECT ZTIMESTAMP, ZINPUTVALUE, ZRESULTVALUE, ZMODE
            FROM ZHISTORYRECORD
            ORDER BY ZTIMESTAMP ASC"""
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            timestamp = CommonFunctions.ReadMacAbsoluteTime(row["ZTIMESTAMP"])
            expression = row["ZINPUTVALUE"]
            result = row["ZRESULTVALUE"]
            mode = row["ZMODE"]
            calc_item = CalculatorHistoryInfo(timestamp, expression, result, mode, user, file_path)
            calculator_histories.append(calc_item)
    except sqlite3.Error as ex:
        log.exception('Error reading calculator history database: ' + str(ex))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    processed_paths = []
    calculator_histories = []
    saved_state_path = '{}/Library/Containers/com.apple.calculator/Data/Library/Application Support/default.store'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = saved_state_path.format(user.home_dir)
        user_name = user.user_name
    
        if mac_info.IsValidFilePath(source_path):
            ExtractAndReadDb(mac_info, calculator_histories, user_name, source_path, process_calculator_db)

    if len(calculator_histories) > 0:
        PrintAll(calculator_histories, mac_info.output_params)
    else:
        log.info('No Calculator history found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    calculator_histories = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        OpenLocalDbAndRead(calculator_histories, '', input_path, process_calculator_db)
    if len(calculator_histories) > 0:
        PrintAll(calculator_histories, output_params)
    else:
        log.info('No Calculator history found')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")