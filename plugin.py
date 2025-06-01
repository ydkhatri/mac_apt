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
import platform
import pyewf
import pytsk3
import pyvmdk
import pyaff4
import traceback

def ImportPlugins(plugins, mode):
    ''' Imports plugins contained in the 'plugins' folder. 
        Args: 
            mode: One of 'IOS', 'MACOS' or 'ARTIFACTONLY'
        Returns a list containing all plugin names that satisfy the mode
    '''
    #print ("Trying to import plugins")
    if getattr(sys, 'frozen', False):
    # Running in a bundle
        base_path = sys._MEIPASS
    else:
        # Running in normal Python environment
        base_path = os.path.dirname(os.path.abspath(__file__))
    plugin_path = os.path.join(base_path, "plugins")
    sys.path.append(plugin_path)

    try:
        dir_list = os.listdir(plugin_path)
        for filename in dir_list:
            if filename.endswith(".py") and not filename.startswith("_"):
                #print ("Found plugin --> %s" % filename)
                try:
                    plugin = __import__(filename.replace(".py", ""))
                    #print ("Plugin name is ----> " + plugin.__Plugin_Name)
                    if not IsPluginValidForMode(plugin, mode): 
                        continue
                    if IsValidPlugin(plugin):
                        plugins.append(plugin)
                    else:
                        print ("Failed to import plugin - {}\nPlugin is missing a required variable".format(filename))
                except Exception as ie: #ImportError, SyntaxError, ..
                    exc_type, ex, tb = sys.exc_info()
                    imported_tb_info = traceback.extract_tb(tb)[-1]
                    fail_filename = imported_tb_info[0]
                    line_number = imported_tb_info[1]
                    print ("!!Error in plugin '" + filename + "' - " + str(exc_type.__name__) + " - " + str(ie))
                    print ("Failed to import plugin - {} ! Check code!".format(filename))
                    continue
    except Exception as ex:
        print ("Does plugin directory exist?\n Exception:\n" +str(ex))
    plugins.sort(key=lambda plugin: plugin.__Plugin_Name) # So plugins are in same order regardless of platform!
    return len(plugins)

def IsValidPlugin(plugin):
    '''Check to see if required plugin variables are present'''
    for attr in ['__Plugin_Name', '__Plugin_Friendly_Name', '__Plugin_Version', '__Plugin_Description', \
                '__Plugin_Author', '__Plugin_Author_Email', '__Plugin_Modes', '__Plugin_ArtifactOnly_Usage']:
        try:
            val = getattr(plugin, attr)
        except Exception:
            print("Required variable '" + attr + "' is missing, check plugin code!")
            return False
    return True

def IsPluginValidForMode(plugin, mode):
    '''Check to see if a plugin can run on specified mode (IOS, MACOS, ARTIFACTONLY)'''
    if hasattr(plugin, '__Plugin_Modes'):
        val = getattr(plugin, '__Plugin_Modes').upper().split(",")
        return mode.upper() in val
    return False

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
        log_file_handler = logging.FileHandler(log_file_path, encoding='utf8')
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

def LogLibraryVersions(log):
    '''Log the versions of libraries used'''
    log.info('Python version = {}'.format(sys.version))
    log.info('Pytsk  version = {}'.format(pytsk3.get_version()))
    log.info('Pyewf  version = {}'.format(pyewf.get_version()))
    log.info('Pyvmdk version = {}'.format(pyvmdk.get_version()))
    log.info('PyAFF4 version = {}'.format(pyaff4._version.raw_versions()['version']))

def LogPlatformInfo(log):
    if getattr(sys, 'frozen', False):
        log.info('Running from a (compiled) version')

    if platform.system == 'Darwin':
        ver = platform.mac_ver()
        if ver is not None and len(ver) > 2:
            log.info(f"Running on macOS {ver[0]}, Architecture {ver[2]}")
        else:
            log.error(f"Running on macOS but platform.mac_ver() failed to return valid data! {str(platform.mac_ver())}")
    elif platform.system == 'Windows':
        ver = platform.win32_ver()
        if ver is not None and len(ver) > 3:
            log.info(f"Running on Windows {ver[0]}, Version={ver[1]}, Service Pack={ver[2]}, Other={ver[3]}")
    else:
        log.info(f"Running on Linux, uname info={platform.uname()}")
    log.info()