# mac_apt
macOS Artifact Parsing Tool

mac_apt is a DFIR tool to process Mac computer full disk images (or live machines) and extract data/metadata useful for forensic investigation. It is a python based framework, which has plugins to process individual artifacts (such as Safari internet history, Network interfaces, Recently accessed files & volumes, ..)

#### Project Status: WIP
#### Requirements: 32/64 bit Python 3.7

#### Features:
* Cross platform (no dependency on pyobjc)
* Works on E01, DD, split-DD, DMG (no compression) & mounted images (good for nix, limited support on windows)
* XLSX, CSV, Sqlite outputs
* Analyzed files/artifacts are exported for later review
* zlib, lzvn, lzfse compressed files are supported!
* APFS is now supported, you can process HighSierra images now!

Available Plugins (artifacts parsed) | Description 
------------------ | ---------------
AUTOSTART | Retrieves programs, daemons, services set to start at boot/login
BASHSESSIONS | Reads bash (Terminal) sessions & history for every user
BASICINFO | Basic machine & OS configuration like SN, timezone, computer name, last logged in user, HFS info
BLUETOOTH | Gets Bluetooth Artifacts
DOCKITEMS | Reads the Dock plist for every user
DOMAINS | Active Directory Domain(s) that the mac is connected to
FSEVENTS | Reads file system event logs (from .fseventsd)
IDEVICEBACKUPS | Reads and exports iPhone/iPad backup databases
IDEVICEINFO | Reads and exports connected iDevice details
IMESSAGE | Read iMessage chats
INETACCOUNTS | Retrieve configured internet accounts (iCloud, Google, Linkedin, facebook..)
INSTALLHISTORY | Software Installation History
NETUSAGE | Read network usage data statistics per application
NETWORKING | Interfaces, last IP address, MAC address, DHCP ..
NOTES | Reads notes databases
NOTIFICATIONS | Reads mac notification data for each user
PRINTJOBS | Parses CUPS spooled print jobs to get information about files/commands sent to a printer
QUARANTINE | Reads the quarantine database and .LastGKReject file
RECENTITEMS | Recently accessed Servers, Documents, Hosts, Volumes & Applications from .plist and .sfl files. Also gets recent searches and places for each user
SAFARI | Internet history, downloaded file information, cookies and more from Safari caches
SPOTLIGHT | Reads the spotlight index databases
SPOTLIGHTSHORTCUTS | User typed data in the spotlight bar & targeted document/app
UNIFIEDLOGS | Reads macOS unified logging logs from .tracev3 files
USERS | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths
WIFI | Gets wifi network information

### Coming soon..
* More plugins
* More documentation
* Python 3 version

For installation and other information, see https://github.com/ydkhatri/mac_apt/wiki

To download, proceed here - https://github.com/ydkhatri/mac_apt/releases

## Bugs
Feel free to send comments and feedback to yogesh AT swiftforensics DOT com, or open an [issue](https://github.com/ydkhatri/mac_apt/issues).
