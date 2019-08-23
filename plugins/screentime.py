'''
   Copyright (c) 2019 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import *
import os
import sqlite3
import logging

__Plugin_Name = "SCREENTIME" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Screen Time Data"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses application Screen Time data"
__Plugin_Author = "Jack Farley"
__Plugin_Author_Email = "jfarley248@gmail.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide Screen Time database found at:' \
                            '/private/var/folders/XX/XXXXXXXXXXXXXXXXXXX_XXXXXXXXX/0/com.apple.ScreenTimeAgent/Store/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class ScreenTime:
    def __init__(self, app, total_time, start_date, end_date, num_notifics, num_pickups, num_pickups_no_app,
                 device_name, apple_id, full_name, family_type, source):
        self.app = app
        self.total_time= total_time
        self.start_date = start_date
        self.end_date = end_date
        self.num_notifics= num_notifics
        self.num_pickups = num_pickups
        self.num_pickups_no_app = num_pickups_no_app
        self.device_name= device_name
        self.apple_id = apple_id
        self.full_name = full_name
        self.family_type = family_type
        self.source = source

def PrintAll(screen_time_data, output_params, source_path):
    screen_time_info = [ ('Application',DataType.TEXT),('Total_Time',DataType.TEXT),('Start_Date',DataType.DATE),
                       ('End_Date',DataType.DATE),('Notification_Count',DataType.INTEGER), ('Pickup_Count',DataType.INTEGER),
                       ('Pickups_Without_Usage',DataType.INTEGER),('Device_Name',DataType.TEXT),('Apple_ID',DataType.TEXT),
                       ('Full_Name', DataType.TEXT),
                       ('Family_Member_Type', DataType.TEXT),('Source',DataType.TEXT)
                     ]

    screen_time_list = []
    for sc in screen_time_data:
        sc_items = [sc.app, sc.total_time, sc.start_date,
                      sc.end_date,
                      sc.num_notifics, sc.num_pickups,
                      sc.num_pickups_no_app, sc.device_name, sc.apple_id,
                      sc.full_name, sc.family_type, sc.source
                     ]
        screen_time_list.append(sc_items)
    WriteList("ScreenTime Info", "ScreenTime", screen_time_list, screen_time_info, output_params, source_path)


def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid Screen Time DB?")
    return None

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid Screen Time DB?")
    return None


def ReadScreenTime(db, screen_time_arr, source):
    try:
        query = "SELECT" \
        "IFNULL(zut.ZBUNDLEIDENTIFIER, zut.ZDOMAIN) as app," \
        "time(zut.ZTOTALTIMEINSECONDS, 'unixepoch') as total_time," \
        "datetime(zub.ZSTARTDATE + 978307200, 'unixepoch')  as start_date," \
        "datetime(zub.ZLASTEVENTDATE + 978307200, 'unixepoch')  as end_date," \
        "zuci.ZNUMBEROFNOTIFICATIONS as num_notifics," \
        "zuci.ZNUMBEROFPICKUPS as num_pickups," \
        "zub.ZNUMBEROFPICKUPSWITHOUTAPPLICATIONUSAGE as num_pickups_no_app," \
        "zcd.ZNAME as device_name, zcu.ZAPPLEID as apple_id," \
        "zcu.ZGIVENNAME || " " || zcu.ZFAMILYNAME as full_name," \
        "zcu.ZFAMILYMEMBERTYPE as family_type" \
        "FROM ZUSAGETIMEDITEM as zut" \
        "LEFT JOIN ZUSAGECATEGORY as zuc on zuc.Z_PK = zut.ZCATEGORY" \
        "LEFT JOIN ZUSAGEBLOCK as zub on zub.Z_PK = zuc.ZBLOCK" \
        "LEFT JOIN ZUSAGE as zu on zu.Z_PK = zub.ZUSAGE" \
        "LEFT JOIN ZCOREDEVICE as zcd on zcd.Z_PK = zu.ZDEVICE" \
        "LEFT JOIN ZCOREUSER as zcu on zcu.Z_PK = zu.ZUSER" \
        "LEFT JOIN ZUSAGECOUNTEDITEM as zuci on zuci.ZBLOCK = zuc.ZBLOCK AND zuci.ZBUNDLEIDENTIFIER = zut.ZBUNDLEIDENTIFIER" \
        "ORDER BY zub.ZSTARTDATE;"




        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            sc = ScreenTime(row['app'], row['total_time'], row['start_date'], row['end_date'], row['num_notifics'],
                            row['num_pickups'], row['num_pickups_no_app'], row['device_name'],
                            row['apple_id'], row['full_name'], row['family_type'], source)
            screen_time_arr.append(sc)
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def ProcessSCDbFromPath(mac_info, screen_time_arr, source_path):
    mac_info.ExportFile(source_path, __Plugin_Name)
    db, wrapper = OpenDbFromImage(mac_info, source_path)
    if db != None:
        ReadScreenTime(db, screen_time_arr, source_path)
        db.close()


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    screentime_db_path = '/private/var/folders/6l/gvwcluywvchewfkdhgqwevfuw_bvefvweufnweofnwef/0/com.apple.ScreenTimeAgent'
    #if mac_info.
    screen_time_arr = []

    ProcessSCDbFromPath(mac_info, screen_time_arr, screentime_db_path)

    if screen_time_arr:
        PrintAll(screen_time_arr, mac_info.output_params, '')
    else:
        log.info("No Screen Time artifacts found.")

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        screen_time_arr = []
        db = OpenDb(input_path)
        if db != None:
            filename = os.path.basename(input_path)
            ReadScreenTime(db, screen_time_arr, input_path, "")
        if screen_time_arr:
            PrintAll(screen_time_arr, output_params, '')
        else:
            log.info("No Screen Time artifacts found.")

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")