# Credits & Acknowledgments
-------------------------

* Yogesh Khatri (@swiftforensics) - Author & Maintainer of mac_apt framework and plugins
* Zachary Burnham (@zmbf0r3ns1cs) - Wrote the install shell script for mac_apt on macOS and Linux
* Adam Ferrante (@ferran7e) - Plugin Documentation on wiki and wrote DOCKITEMS & BLUETOOTH plugins
* Jack Farley (@JackFarley248) - Added Encryption support and plugins - IDEVICE_BACKUPS, IDEVICE_INFO, PRINTJOBS, IMESSAGE, SCREENTIME, QUICKLOOK
* Michael Geyer - Wrote the WIFI plugin
* Nicole Ibrahim (@nicoleibrahim) - Wrote the DOCUMENTREVISIONS plugin, bug fix for disk decryption
* Minoru Kobayashi (@mnrkbys) - Bugfixes, parsers, and writing the UTMPX, CFURL_CACHE, FILESHARING, MSRDC, TCC plugins
* Yuya Hashimoto (@a5hlynx) - Bugfixes and wrote the ASL plugin
* Brandon Mignini - Wrote the AUTOSTART plugin
* Noah Sidall (@noah_sidd) - Wrote the INSTALLHISTORY plugin
* Austin Truax - Wrote the proof of concept parsing wifi information from airport plist

#### APFS support 
* Kurt-Helge Hansen - For publishing the paper detailing APFS internal structure and working, as well as providing some proof of concept code for parsing APFS containers. https://www.researchgate.net/publication/319573636_Decoding_the_APFS_file_system
* Jonas Plum (@cugu_pio) & Thomas Tempelmann (@tempelorg) - For providing initial reference implementation using kaitai-struct (https://github.com/cugu/apfs.ksy). This was the basis for mac_apt's APFS implementation.
