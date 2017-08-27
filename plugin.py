'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   plugin.py
   ---------
   This module handles plugin operations, importing them, checking for 
   errors. There are also some common functions used by both the main
   framework as well as the single plugin one.
'''
import logging
import os
import sys

def ImportPlugins(plugins, only_standalone=False):
    #print ("Trying to import plugins")
    plugin_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "plugins")
    sys.path.append(plugin_path)

    try:
        dir_list = os.listdir(plugin_path)
        for filename in dir_list:
            if filename.endswith(".py") and not filename.startswith("_"):
                #print ("Found plugin --> %s" % filename)
                try:
                    plugin = __import__(filename.replace(".py", ""))
                    #print ("Plugin name is ----> " + plugin.__Plugin_Name)
                    if only_standalone and not getattr(plugin, '__Plugin_Standalone'): 
                        continue
                    if IsValidPlugin(plugin):
                        plugins.append(plugin)
                    else:
                        print ("Failed to import plugin - {}\nPlugin is missing a required variable".format(filename))
                except Exception as ie: #ImportError, SyntaxError, ..
                    print ("!!Error in plugin '" + filename + "' at line " + str(sys.exc_info()[2].tb_lineno) + " - " + str(ie))
                    print ("Failed to import plugin - {} ! Check code!".format(filename))
                    continue
    except Exception as ex:
        print ("Does plugin directory exist?\n Exception:\n" +str(ex))
    return len(plugins)

def IsValidPlugin(plugin):
    '''Check to see if required plugin variables are present'''
    for attr in ['__Plugin_Name', '__Plugin_Friendly_Name', '__Plugin_Version', '__Plugin_Description', \
                '__Plugin_Author', '__Plugin_Author_Email', '__Plugin_Standalone', '__Plugin_Standalone_Usage']:
        try:
            val = getattr(plugin, attr)
        except Exception:
            print("Required variable '" + attr + "' is missing, check plugin code!")
            return False
    return True

def CheckUserEnteredPluginNames(plugins_to_run, plugins):
    '''Check user entered plugin names for invalid/missing ones '''
    for item in plugins_to_run:
        found = False
        for plugin in plugins:
            if plugin.__Plugin_Name == item:
                found = True
                break
        if found == False:
            print ("Error : Plugin not found : " + item)
            print ("Do you have the right plugin name?")
            return False
    return True

def CheckOutputPath(output_path):
    '''Checks validity of outputpath, if it does not exist, it creates it'''
    ret = False
    try:
        if os.path.isdir(output_path): # Check output path provided
            ret = True
        else: # Either path does not exist or it is not a folder
            if os.path.isfile(output_path):
                print("Error: There is already a file existing by that name. Cannot create folder : " + output_path)
            else: # Try creating folder
                try:
                    os.makedirs(output_path)
                    ret = True
                except Exception as ex:
                    print("Error: Cannot create output folder : " + output_path + "\nError Details: " + str(ex))

    except Exception as ex:
        print("Error: Unknown exception, error details are: " + str(ex))
    return ret

def CreateLogger(log_file_path, log_file_level=logging.DEBUG, log_console_level=logging.INFO):
    '''Creates the logging classes for both console & file'''
    try:
        # Log file setting
        logger = logging.getLogger('MAIN')
        log_file_handler = logging.FileHandler(log_file_path)
        log_file_format  = logging.Formatter('%(asctime)s|%(name)s|%(levelname)s|%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        log_file_handler.setFormatter(log_file_format)
        logger.addHandler(log_file_handler)

        #log_file_handler.setLevel(log_file_level) # overrides logger.setLevel() , use if needed!

        # console handler
        log_console_handler = logging.StreamHandler()
        log_console_handler.setLevel(log_console_level)
        log_console_format  = logging.Formatter('%(name)s-%(levelname)s-%(message)s')
        log_console_handler.setFormatter(log_console_format)
        logger.addHandler(log_console_handler)
    except Exception as ex:
        print ("Error while trying to create log file\nError Details:\n")
        traceback.print_exc()
        sys.exit ("Program aborted..could not create log file!")
    return logger
