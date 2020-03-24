# mac_apt
macOS Artifact Parsing Tool

mac_apt is a DFIR tool to process Mac computer full disk images (**or _live_ machines**) and extract data/metadata useful for forensic investigation. It is a python based framework, which has plugins to process individual artifacts (such as Safari internet history, Network interfaces, Recently accessed files & volumes, ..)

#### Project Status: _BETA_
#### Requirements: Python 3.7 (32/64 bit)

#### Features:
* Cross platform (no dependency on pyobjc)
* Works on E01, VMDK, DD, split-DD, DMG (no compression) & mounted images (good for nix, limited support on windows)
* XLSX, CSV, Sqlite outputs
* Analyzed files/artifacts are exported for later review
* zlib, lzvn, lzfse compressed files are supported!
* Native HFS & APFS parser
* Reads the Spotlight database and Unified Logging (tracev3) files

#### Latest (only in code, no compiled exe/bundle yet)
:heavy_check_mark: macOS Catalina (10.15) images can be parsed now  
:heavy_check_mark: AFF4 images (_of unencrypted APFS volumes_) now supported

Available Plugins (artifacts parsed) | Description 
------------------ | ---------------
APPLIST | Reads apps & printers installed and/or available for each user from appList.dat
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
MSOFFICE | Reads Word, Excel, Powerpoint and other office MRU/accessed file paths
NETUSAGE | Read network usage data statistics per application
NETWORKING | Interfaces, last IP address, MAC address, DHCP ..
NOTES | Reads notes databases
NOTIFICATIONS | Reads mac notification data for each user
PRINTJOBS | Parses CUPS spooled print jobs to get information about files/commands sent to a printer
QUARANTINE | Reads the quarantine database and .LastGKReject file
QUICKLOOK | Reads the QuickLook index.sqlite and carves thumbnails from thumbnails.data
RECENTITEMS | Recently accessed Servers, Documents, Hosts, Volumes & Applications from .plist and .sfl files. Also gets recent searches and places for each user
SAFARI | Internet history, downloaded file information, cookies and more from Safari caches
SCREENTIME | Reads ScreenTime database for program and app usage
SPOTLIGHT | Reads the spotlight index databases
SPOTLIGHTSHORTCUTS | User typed data in the spotlight bar & targeted document/app
TERMINALSTATE | Reads Terminal saved state files which includes full text content of terminal windows
UNIFIEDLOGS | Reads macOS unified logging logs from .tracev3 files
USERS | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths
WIFI | Gets wifi network information

### Coming soon..
* More plugins
* More documentation
* APFS Encryption support

For installation (to run from code) see https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3.7  
**Please read the documentation here:** https://github.com/ydkhatri/mac_apt/wiki

To download, proceed here - https://github.com/ydkhatri/mac_apt/releases

## Bugs
Feel free to send comments and feedback to yogesh AT swiftforensics DOT com, or open an [issue](https://github.com/ydkhatri/mac_apt/issues).
