"""
    Copyright (c) 2024 Minoru Kobayashi

    This file is part of mac_apt (macOS Artifact Parsing Tool).
    Usage or distribution of this software/code is subject to the
    terms of the MIT License.

    screensharing.py
    ---------------
    This plugin parses Screen Sharing preferences and extracts a host list.
"""
from __future__ import annotations

import logging
import os
import plistlib

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import DataType, MacInfo, OutputParams
from plugins.helpers.writer import WriteList

__Plugin_Name = "SCREENSHARING"  # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Screen Sharing hitory"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses the Screen Sharing preferences and extracts connection history (IP address, hostname, login username, group name, and last connection date)"
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"  # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = "Provide com.apple.ScreenSharing.plist file."

log = logging.getLogger("MAIN." + __Plugin_Name)  # Do not rename or remove this ! This is the logger object

# ---- Do not change the variable names in above section ----#

xp_diag_filename_regex = r"XProtect_(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})_[\w\-]+\.diag"


class ScreenSharingItem:
    def __init__(self, host_uuid: str, address: str, display_name: str, login_username: str, groups: str, last_connection_date: str, source: str) -> None:
        self.host_uuid = host_uuid
        self.address = address
        self.display_name = display_name
        self.login_username = login_username
        self.groups = groups
        self.last_connection_date = last_connection_date
        self.source = source


# def ParseScreenSharingPlist(plist: dict, screen_sharing_artifacts: list[ScreenSharingItem], username: str, ss_plist_path: str) -> None:
def ParseScreenSharingPlist(plist: dict, screen_sharing_artifacts: list[ScreenSharingItem], ss_plist_path: str) -> None:
    # try:
    connectionsStore = plistlib.loads(plist.get("connectionsStore"))

    group_by_host: dict[str, list[str]] = {}
    for group_uuid in connectionsStore.get("connectionGroups").keys():
        for host_uuid in connectionsStore["connectionGroups"][group_uuid]["members"]:
            if host_uuid not in group_by_host:
                group_by_host[host_uuid] = []
            group_by_host[host_uuid].append(connectionsStore["connectionGroups"][group_uuid]["groupName"])

    if connectionsStore.get("connectionDetails") and connectionsStore.get("sessionMetadatas"):
        for host_uuid in connectionsStore["connectionDetails"].keys():
            host_info = connectionsStore["connectionDetails"][host_uuid]["connectionParameters"]["networkAddress"]["_0"]
            address = host_info.get("address", "")
            login_username = host_info.get("username", "")
            display_name = host_info.get("displayName", "")
            last_connection_date = connectionsStore["sessionMetadatas"][host_uuid]["lastConnectedDate"].strftime("%Y-%m-%d %H:%M:%S.%f")
            groups = ""
            if group_by_host.get(host_uuid):
                groups = ", ".join(sorted(group_by_host[host_uuid]))
            item = ScreenSharingItem(host_uuid, address, display_name, login_username, groups, last_connection_date, ss_plist_path)
            screen_sharing_artifacts.append(item)

    # except plistlib.InvalidFileException:
    #     log.error(f"{ss_plist_path} has invalid data.")


def ExtractAndReadScreenSharingPlist(mac_info: MacInfo, screen_sharing_artifacts: list[ScreenSharingItem], username: str, ss_plist_path: str) -> None:
    success, plist, error = mac_info.ReadPlist(ss_plist_path)
    if success:
        # ParseScreenSharingPlist(plist, screen_sharing_artifacts, username, ss_plist_path)
        ParseScreenSharingPlist(plist, screen_sharing_artifacts, ss_plist_path)
        mac_info.ExportFile(ss_plist_path, __Plugin_Name, "", False)
    else:
        log.error("Could not open plist " + ss_plist_path)
        log.error("Error was: " + error)


def OpenAndReadScreenSharingPlist(screen_sharing_artifacts: list[ScreenSharingItem], username: str, ss_plist_path: str) -> None:
    success, plist, error = CommonFunctions.ReadPlist(ss_plist_path)
    if success:
        # ParseScreenSharingPlist(plist, screen_sharing_artifacts, username, ss_plist_path)
        ParseScreenSharingPlist(plist, screen_sharing_artifacts, ss_plist_path)
    else:
        log.error("Could not open plist " + ss_plist_path)
        log.error("Error was: " + error)


def PrintAll(screen_sharing_artifacts: list, output_params: OutputParams, source_path: str) -> None:
    ss_plist_info = [
        ("Host_UUID", DataType.TEXT),             # Host UUID
        ("Address", DataType.TEXT),               # IP Address
        ("Display_Name", DataType.TEXT),          # Display Name of the host
        ("Login_Username", DataType.TEXT),        # Username used to login
        ("Groups", DataType.TEXT),                # Groups the host belongs to
        ("Last_Connection_Date", DataType.TEXT),  # Last connection date
        ("Source", DataType.TEXT),                # Source of the data
    ]

    data_list = []
    log.info(f"{len(screen_sharing_artifacts)} Screen Sharing item(s) found")
    for item in screen_sharing_artifacts:
        data_list.append(
            [
                item.host_uuid,
                item.address,
                item.display_name,
                item.login_username,
                item.groups,
                item.last_connection_date,
                item.source,
            ]
        )

    WriteList("ScreenSharing", "ScreenSharing", data_list, ss_plist_info, output_params, source_path)


def Plugin_Start(mac_info: MacInfo) -> None:
    """Main Entry point function for plugin"""
    screen_sharing_artifacts: list[ScreenSharingItem] = []
    screen_sharing_plist_base_path = "{}/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist"
    processed_paths = set()

    for user in mac_info.users:
        if user.home_dir in processed_paths:
            continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        ss_plist_path = screen_sharing_plist_base_path.format(user.home_dir)

        if mac_info.IsValidFilePath(ss_plist_path):
            ExtractAndReadScreenSharingPlist(mac_info, screen_sharing_artifacts, user.user_name, ss_plist_path)

    if len(screen_sharing_artifacts) > 0:
        PrintAll(screen_sharing_artifacts, mac_info.output_params, "")
    else:
        log.info("No Screen Sharing artifacts were found!")


def Plugin_Start_Standalone(input_files_list: list[str], output_params: OutputParams) -> None:
    """Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image"""
    log.info("Module Started as standalone")
    screen_sharing_artifacts: list[ScreenSharingItem] = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            OpenAndReadScreenSharingPlist(screen_sharing_artifacts, "N/A", input_path)
        else:
            log.info(f"{input_path} does not exist or file size = 0.")

    if len(screen_sharing_artifacts) > 0:
        PrintAll(screen_sharing_artifacts, output_params, "")
    else:
        log.info("No Screen Sharing artifacts were found!")


def Plugin_Start_Ios(ios_info):
    """Entry point for ios_apt plugin"""
    pass


if __name__ == "__main__":
    print("This plugin is a part of a framework and does not run independently on its own!")
