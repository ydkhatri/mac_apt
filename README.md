# mac_apt - macOS Artifact Parsing Tool  
[![Latest version](https://img.shields.io/badge/version-v0.9-blue)](https://github.com/ydkhatri/mac_apt/releases/tag/v0.9)
[![status](https://img.shields.io/badge/status-stable-green)]()

[![Latest version](https://img.shields.io/badge/version-v0.9.dev-blue)](https://github.com/ydkhatri/mac_apt/releases/tag/v0.9.dev)
[![status](https://img.shields.io/badge/status-development-orange)]()

mac_apt is a DFIR (Digital Forensics and Incident Response) tool to process Mac computer full disk images (**or _live_ machines**) and extract data/metadata useful for forensic investigation. It is a python based framework, which has plugins to process individual artifacts (such as Safari internet history, Network interfaces, Recently accessed files & volumes, ..)

mac_apt now also includes **ios_apt**, for processing ios images.

#### Requirements: Python 3.7 or above (32/64 bit)

#### Features
* Cross platform (no dependency on pyobjc)
* Works on E01, VMDK, AFF4, DD, split-DD, DMG (no compression) & mounted images  
* XLSX, CSV, Sqlite outputs
* Analyzed files/artifacts are exported for later review
* zlib, lzvn, lzfse compressed files are supported!
* Native HFS & APFS parser
* Reads the Spotlight database and Unified Logging (tracev3) files

#### Latest
:heavy_check_mark: Support for macOS Big Sur Sealed volumes (11.0)  
:heavy_check_mark: Introducing **ios_apt** for processing iOS/ipadOS images  
:heavy_check_mark: FAST mode :hourglass_flowing_sand:   
:heavy_check_mark: Encrypted :lock: APFS images can now be processed using password/recovery-key :key:   
:heavy_check_mark: macOS Catalina (10.15) separately mounted SYSTEM & DATA volumes now supported  
:heavy_check_mark: AFF4 images (including macquisition created) are supported

Available Plugins (artifacts parsed) | Description 
------------------ | ---------------
APPLIST | Reads apps & printers installed and/or available for each user from appList.dat
ARD | Reads ARD (Apple Remote Desktop) cached databases about app usage
AUTOSTART | Retrieves programs, daemons, services set to start at boot/login
BASICINFO | Basic machine & OS configuration like SN, timezone, computer name, last logged in user, HFS info
BLUETOOTH | Gets Bluetooth Artifacts
CHROME | Read Chrome History, Top Sites, Downloads and Extension info
COOKIES | Reads .binarycookies, .cookies files and HSTS.plist for each user
DOCKITEMS | Reads the Dock plist for every user
DOCUMENTREVISIONS | Reads DocumentRevisions database
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
SAVEDSTATE | Gets window titles from Saved Application State info
SCREENTIME | Reads ScreenTime database for program and app usage
SPOTLIGHT | Reads the spotlight index databases
SPOTLIGHTSHORTCUTS | User typed data in the spotlight bar & targeted document/app
SUDOLASTRUN | Gets last time sudo was used and a few other times earlier (if available)
TERMINALSTATE | Reads Terminal saved state files which includes full text content of terminal windows
TERMSESSIONS | Reads Terminal (bash & zsh) history & sesions for every user
UNIFIEDLOGS | Reads macOS unified logging logs from .tracev3 files
USERS | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths
WIFI | Gets wifi network information

### Coming soon..
* More plugins
* More documentation

For installation (to run from code) see https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3  
**Please read the documentation here:** https://github.com/ydkhatri/mac_apt/wiki

To download, proceed here - https://github.com/ydkhatri/mac_apt/releases

## Bugs
Feel free to send comments and feedback to yogesh AT swiftforensics DOT com, or open an [issue](https://github.com/ydkhatri/mac_apt/issues).  

[![Tweet](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2Fswiftforensics)](https://twitter.com/swiftforensics)
