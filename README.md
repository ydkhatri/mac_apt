# mac_apt
macOS Artifact Parsing Tool

mac_apt is a tool to process Mac computer full disk images and extract data/metadata useful for forensic investigation. It is a python based framework, which has plugins to process individual artifacts (such as Safari internet history, Network interfaces, Recently accessed files & volumes, ..)

#### Project Status: alpha, experimental
#### Requirements: 32 bit Python 2.7

#### Features:
* Cross platform (no dependency on pyobjc)
* Works on E01, DD, split-DD, DMG (no compression) & mounted images (limited support)
* XLSX, CSV, Sqlite outputs
* Analyzed files/artifacts are exported for later review
* zlib, lzvn, lzfse compressed files are supported!

Available Plugins (artifacts parsed) | Description 
------------------ | ---------------
WIFI | Gets wifi network information
BASICINFO | Basic machine & OS configuration like SN, timezone, computer name, last logged in user, HFS info
BASHSESSIONS | Reads bash (Terminal) sessions & history for every user
DOMAINS | Active Directory Domain(s) that the mac is connected to
INSTALLHISTORY | Software Installation History
NETWORKING | Interfaces, last IP address, MAC address, DHCP ..
RECENTITEMS | Recently accessed Servers, Documents, Hosts, Volumes & Applications from .plist and .sfl files. Also gets recent searches and places for each user
SAFARI | Internet history, downloaded file information, cookies and more from Safari caches
SPOTLIGHTSHORTCUTS | User typed data in the spotlight bar & targeted document/app
USERS | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths

More plugins coming soon..

For installation and other information, see https://github.com/ydkhatri/mac_apt/wiki
