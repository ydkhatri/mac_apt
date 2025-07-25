# mac_apt - macOS (and iOS) Artifact Parsing Tool
[![Latest version](https://img.shields.io/badge/version-v1.13.6-blue)](https://github.com/ydkhatri/mac_apt/releases/tag/v1.13.6)
[![status](https://img.shields.io/badge/status-stable-green)]()

mac_apt is a DFIR (Digital Forensics and Incident Response) tool to process Mac computer full disk images (**or _live_ machines**) and extract data/metadata useful for forensic investigation. It is a python based framework, which has plugins to process individual artifacts (such as Safari internet history, Network interfaces, Recently accessed files & volumes, ..)

mac_apt now also includes **[ios_apt](https://swiftforensics.com/2020/12/introducing-iosapt-ios-artifact-parsing.html)**, for processing ios images.

#### Requirements: Python 3.9 or above (64 bit)
_Note: Tested upto Python 3.13 on Windows and macOS (ARM and x64)._
#### Features
* Cross platform (no dependency on pyobjc)
* Works on E01, VMDK, AFF4, DD, split-DD, DMG (no compression), SPARSEIMAGE, Velociraptor collected files (VR) & mounted images
* XLSX, CSV, TSV, JSONL, Sqlite outputs
* Analyzed files/artifacts are exported for later review
* zlib, lzvn, lzfse compressed files are supported!
* Native HFS & APFS parser
* Reads the Spotlight database

#### Latest
:heavy_check_mark: Can read Velociraptor created targeted collection zip \(when created via [MacOS.Search.FileFinder](https://docs.velociraptor.app/artifact_references/pages/macos.search.filefinder/)\)   
:heavy_check_mark: Can read Axiom created targeted collection zip files  
:heavy_check_mark: ios_apt can read GrayKey extracted file system  
:heavy_check_mark: Can read [RECON](https://sumuri.com/software/recon-itr/) and [ASLA](https://github.com/giuseppetotaro/asla) created .sparseimage files  
:heavy_check_mark: Support for macOS Big Sur Sealed volumes (11.0)  
:heavy_check_mark: Introducing **ios_apt** for processing iOS/ipadOS images  
:heavy_check_mark: FAST mode :hourglass_flowing_sand:  
:heavy_check_mark: Encrypted :lock: APFS images can now be processed using password/recovery-key :key:  
:heavy_check_mark: macOS Catalina (10.15+) separately mounted SYSTEM & DATA volumes now supported  
:heavy_check_mark: AFF4 images (including Macquisition/DigitalCollector created) are supported  

Available Plugins (artifacts parsed) | Description
------------------ | ---------------
APPLIST | Reads apps & printers installed and/or available for each user from appList.dat
ARD | Reads ARD (Apple Remote Desktop) cached databases about app usage
ASL | Reads ASL (Apple System Log) from asl.log, asl.db and ".asl" files
AUTOSTART | Retrieves programs, daemons, services set to start at boot/login
BASICINFO | Basic machine & OS configuration like SN, timezone, computer name, last logged in user, HFS info
BLUETOOTH | Gets Bluetooth Artifacts
CALLHISTORY | Reads call history database
CFURLCACHE | Reads CFURL cache to URLs, requests and responses
CHROMIUM | Read Chromium Browsers (Edge, Chrome, Opera,..) History, Top Sites, Downloads and Extension info
COOKIES | Reads .binarycookies, .cookies files and HSTS.plist for each user
CRASHREPORTER | Reads crash reporter plists
DOCKITEMS | Reads the Dock plist for every user
DOCUMENTREVISIONS | Reads DocumentRevisions database
DOMAINS | Active Directory Domain(s) that the mac is connected to
FACETIME | Read available facetime call metadata  
FILESHARING | Read shared folder info
FIREFOX | Read internet history from Mozilla Firefox browser
FSEVENTS | Reads file system event logs (from .fseventsd)
ICLOUD | Extract items stored in iCloud Drive
IDEVICEBACKUPS | Reads and exports iPhone/iPad backup databases
IDEVICEINFO | Reads and exports connected iDevice details
IMESSAGE | Read iMessage chats
INETACCOUNTS | Retrieve configured internet accounts (iCloud, Google, Linkedin, facebook..)
INSTALLHISTORY | Software Installation History
KEYCHAINS | Reads the System keychain and decrypts stored passwords
LAUNCHPAD | Reads the launchpad database for every user  
MSOFFICE | Reads Word, Excel, Powerpoint and other office MRU/accessed file paths
MSRDC | Reads connection history from Microsoft Remote Desktop database and extracts thumbnails
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
SCREENSHARING | Reads the list of connected hosts with Screen Sharing
SCREENTIME | Reads ScreenTime database for program and app usage
SPOTLIGHT | Reads the spotlight index databases
SPOTLIGHTSHORTCUTS | User typed data in the spotlight bar & targeted document/app
SUDOLASTRUN | Gets last time sudo was used and a few other times earlier (if available)
TCC | Reads Transparency, Consent and Control (TCC) database
TERMINALSTATE | Reads Terminal saved state files which includes full text content of terminal windows
TERMSESSIONS | Reads Terminal (bash & zsh) history & sesions for every user
~~UNIFIEDLOGS~~ | ~~Reads macOS unified logging logs from .tracev3 files~~ _REMOVED as better options are [available](https://github.com/ydkhatri/UnifiedLogReader/blob/master/README.md#this-tool-is-now-archived-i-havent-had-time-to-update-this-tool-so-its-a-bit-outdated-there-isnt-incentive-to-update-this-any-more-as-python-processing-of-unifiedlogs-is-slow-and-takes-a-very-long-time-a-much-faster-rust-based-alternative-exists-please-use-that-instead-httpsgithubcommandiantmacos-unifiedlogs)_
UNIFIEDLOGEXPORT | Exports Unifiedlogs and associated files for external processing  
USERS | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths
UTMPX | Reads utmpx file
WIFI | Gets wifi network information
WIFI_INTELLIGENCE | Gets Wifi connect/disconnect information from Apple Intelligence db
XPROTECT | Reads XProtect diagnostic files and XProtect Behavior Service database

### Coming soon..
* Plugins for BIOME and KnowledgeC
* More documentation

For installation (to run from code) see https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3  
**Please read the documentation here:** https://github.com/ydkhatri/mac_apt/wiki

To download windows binaries, proceed here - https://github.com/ydkhatri/mac_apt/releases

## Bugs
Feel free to send comments and feedback to yogesh@swiftforensics.com, or open an [issue](https://github.com/ydkhatri/mac_apt/issues).  

[![Tweet](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2Fswiftforensics)](https://twitter.com/swiftforensics)
