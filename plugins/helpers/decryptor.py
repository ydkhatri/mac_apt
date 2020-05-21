'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

    Written by Jack Farley & Garrett Mahoney

    Decrypts APFS volumes

'''

import hashlib
import logging
import struct
from cryptography.exceptions import InternalError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kaitaistruct import  KaitaiStruct, KaitaiStream, BytesIO
from uuid import UUID as uuid_obj

log = logging.getLogger('MAIN.HELPERS.DECRYPTOR')

APFS_FV_PERSONAL_RECOVERY_KEY_UUID = "EBC6C064-0000-11AA-AA11-00306543ECAC"
KB_TAG_UNKNOWN = 0
KB_TAG_WRAPPING_KEY = 1
KB_TAG_VOLUME_KEY = 2
KB_TAG_VOLUME_UNLOCK_RECORDS = 3
KB_TAG_VOLUME_PASSPHRASE_HINT = 4
KB_TAG_USER_PAYLOAD = 5


"""CODE FROM: https://github.com/arthurdejong/python-pskc"""
def _strxor(a, b):
    """Return a XOR b"""
    return bytes(x ^ y for (x, y) in zip(a, b))


def _split(value):
    return value[:8], value[8:]


RFC3394_IV = bytes.fromhex('a6a6a6a6a6a6a6a6')
RFC5649_IV = bytes.fromhex('a65959a6')

def unwrap(ciphertext, key, iv=None, pad=None, algorithm=algorithms.AES):
    """Apply the AES key unwrap algorithm to the ciphertext.
    The iv can specify an initial value, otherwise the value from RFC 3394 or
    RFC 5649 will be used, depending on the value of pad.
    If pad is False, unpadding as described in RFC 5649 will be disabled,
    otherwise checking and removing the padding is automatically done.
    """
    if iv is not None:
        pad = False

    if len(ciphertext) % 8 != 0 or (pad is False and len(ciphertext) < 24):
        raise ValueError('Ciphertext length wrong')

    cipher = Cipher(algorithm(key), modes.ECB(), default_backend())
    decryptor = cipher.decryptor()
    n = len(ciphertext) // 8 - 1

    if n == 1:
        A, plaintext = _split(decryptor.update(ciphertext))  # noqa: N806
    else:
        A = ciphertext[:8]  # noqa: N806
        R = [ciphertext[(i + 1) * 8:(i + 2) * 8]  # noqa: N806
             for i in range(n)]
        for j in reversed(range(6)):
            for i in reversed(range(n)):
                A = _strxor(A, struct.pack('>Q', n * j + i + 1))  # noqa: N806
                A, R[i] = _split(decryptor.update(A + R[i]))  # noqa: N806
        plaintext = b''.join(R)

    if iv is None:
        if A == RFC3394_IV and pad is not True:
            return plaintext
        elif A[:4] == RFC5649_IV and pad is not False:
            mli = struct.unpack('>I', A[4:])[0]
            # check padding length is valid and plaintext only contains zeros
            if 8 * (n - 1) < mli <= 8 * n and \
               plaintext.endswith((len(plaintext) - mli) * b'\0'):
                return plaintext[:mli]
    elif A == iv:
        return plaintext
    raise ValueError('IV does not match')
"""END CODE FROM: https://github.com/arthurdejong/python-pskc"""



#######################################################################################################################
################## VEK STRCUTURES ONLY #################################################################################
#######################################################################################################################
class blob_header_t_vek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.unk_80 = self._io.read_bytes(10)
        self.unk1 = self._io.read_bytes(1)
        self.hmac = self._io.read_bytes(32)
        self.unk2 = self._io.read_bytes(2)
        self.salt = self._io.read_bytes(8)
        self.unk35 = self._io.read_bytes(35)
        self.bag_data = self._io.read_bytes(40)
        self.unk12 = self._io.read_bytes(12)

class keybag_entry_vek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.UUID = self._io.read_bytes(16)
        self.KeyBag_Tags = self._io.read_u2le()
        self.key_keylen = self._io.read_u2le()

        if self.key_keylen == 16:
            self.padding = self._io.read_bytes(4)
            self.pr_start_paddr = self._io.read_u8le()
            self.pr_block_count = self._io.read_u8le()
            self.padding = self._io.read_bytes(8)
        else:
            self.blob_header = blob_header_t_vek(self._io, self, self._root)


class kb_locker_vek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.kl_version = self._io.read_u2le()
        self.kl_nkeys = self._io.read_u2le()
        self.kl_nbytes = self._io.read_u4le()
        self.padding = self._io.read_bytes(8)
        self.kl_entries = [keybag_entry_vek] * (self.kl_nkeys)
        for i in range(self.kl_nkeys):
            self.kl_entries[i] = keybag_entry_vek(self._io, self, self._root)


class obj_phys_t(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.o_cksum = self._io.read_bytes(8)
        self.o_oid = self._io.read_u8le()
        self.o_xid = self._io.read_u8le()
        self.o_type = self._io.read_u4le()
        self.o_subtype = self._io.read_u4le()


class media_keybag_t_vek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.mk_obj = obj_phys_t(self._io, self, self._root)
        self.mk_locker = kb_locker_vek(self._io, self, self._root)
        
#######################################################################################################################
################## END VEK STRCUTURES #################################################################################
#######################################################################################################################


#######################################################################################################################
################## KEK STRCUTURES ONLY #################################################################################
#######################################################################################################################


class keybag_entry_kek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.UUID = self._io.read_bytes(16)
        self.KeyBag_Tags = self._io.read_u2le()
        self.key_keylen = self._io.read_u2le()
        self.padding = self._io.read_bytes(4)

        #if self.key_keylen == 148:
        # blob header
        self.unk = self._io.read_bytes(8)
        self.hmac = self._io.read_bytes(32)
        self.unk2 = self._io.read_bytes(2)
        self.salt = self._io.read_bytes(8)
        # blob follows
        self.unk7 = self._io.read_bytes(7)
        self.uuid = self._io.read_bytes(16)
        self.unk12 = self._io.read_bytes(12)
        self.bag_data = self._io.read_bytes(40)
        self.unk2_2 = self._io.read_bytes(2)
        self.iterations = self._io.read_bytes(3)
        self.unk2_3 = self._io.read_bytes(2)
        self.kek_salt = self._io.read_bytes(16)
        self.padding2 = self._io.read_bytes(4)


class kb_locker_kek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.kl_version = self._io.read_u2le()
        self.kl_nkeys = self._io.read_u2le()
        self.kl_nbytes = self._io.read_u4le()
        self.padding = self._io.read_bytes(8)
        self.kl_entries = [keybag_entry_kek] * (self.kl_nkeys)
        for i in range(self.kl_nkeys):
            self.kl_entries[i] = keybag_entry_kek(self._io, self, self._root)


class media_keybag_t_kek(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.mk_obj = obj_phys_t(self._io, self, self._root)
        self.mk_locker = kb_locker_kek(self._io, self, self._root)


#######################################################################################################################
################## END KEK STRCUTURES #################################################################################
#######################################################################################################################

def parse_vek_keybag(unwrapped_keybag):
    """
    Returns a kaitai struct structure of the unwrapped keybag
    param: unwrappped_keybag: The bytes like keybag that will be parsed
    return: keybag: The structured keybag
    """

    stream = KaitaiStream(BytesIO(unwrapped_keybag))
    keybag = media_keybag_t_vek(stream)
    return keybag


def parse_volume_keybag(unwrapped_keybag):
    """
    Returns a kaitai struct structure of the unwrapped keybag
    param: unwrappped_keybag: The bytes like keybag that will be parsed
    return: keybag: The structured keybag
    """

    stream = KaitaiStream(BytesIO(unwrapped_keybag))
    keybag = media_keybag_t_kek(stream)
    return keybag


def convert_keybag_uuid_to_string(binary_uuid):
    """
    Converts a bytes like UUID to a string for comparisons
    param: binary_uuid: The bytes like UUID object that will be converted
    return: uuid: The string like UUID used for comparisons
    """

    uuid = uuid_obj(bytes=binary_uuid)
    return uuid.hex.upper()


def find_wrapped_kek_from_vol_keybag(keybag, user_uuid=None):

    user_open_dir_uuid = user_uuid
    user_open_dir_uuid = user_open_dir_uuid.replace("-", "")

    for kl_entry in keybag.mk_locker.kl_entries:
        if kl_entry.KeyBag_Tags == KB_TAG_VOLUME_UNLOCK_RECORDS:
            # Converts the UUID in the unwrapped keybag entry to GUID like format for comparisons
            byte_uuid = kl_entry.UUID
            readable_UUID = convert_keybag_uuid_to_string(byte_uuid)
            if readable_UUID == user_open_dir_uuid:
                return kl_entry.bag_data, kl_entry.iterations, kl_entry.kek_salt
    return None, None, None


class EncryptedVol:
    def __init__(self, ApfsVolume, preboot_plist, password):
        self.ApfsVolume = ApfsVolume
        self.wrapped_keybag_offset = ApfsVolume.container.containersuperblock.body.keylocker_paddr
        self.keylocker_block_count = ApfsVolume.container.containersuperblock.body.keylocker_block_count
        self.block_size = ApfsVolume.container.containersuperblock.body.block_size
        self.uuid = ApfsVolume.container.containersuperblock.body.uuid
        self.preboot_plist = preboot_plist
        self.decryption_key = None
        self.password = password
        log.info("Starting decryption of Volume: " + self.ApfsVolume.volume_name)
        self.decrypter()


    def decrypt_keybag(self, wrapped_keybag, offset, key):
        """
        Decrypts the wrapped binary keybag that will be decrypted using the Container's UUID.
        Uses the setKey function as the cipher
        The UUID is set as both the first and second key in the cipher
        param: wrapped_keybag: The wrapped binary keybag that will be decrypted using the Container's UUID
        """

        cs_factor = self.block_size // 0x200
        uno = offset * cs_factor
        complete_plaintext = b""

        # Cipher is AES-XTS with the container UUID as the first and second key

        try:
            log.debug("Attempting to decrypt the keybag")
            k = 0
            size = len(wrapped_keybag)
            while k < size:
                tweak = struct.pack("<QQ", uno, 0)
                decryptor = Cipher(algorithms.AES(key + key), modes.XTS(tweak), backend=default_backend()).decryptor()
                complete_plaintext += decryptor.update(wrapped_keybag[k:k + 0x200]) + decryptor.finalize()
                uno += 1
                k += 0x200

            log.debug("Successfully decrypted the keybag")
            return complete_plaintext
        except InternalError as ex:
            log.exception("Could not decrypt the keybag.")
        return ''


    def get_wrapped_key_from_prk(self, volume_keybag):
        """

        :param volume_keybag: The parsed volume keybag
        :return:
            bag_data
            iterations
            salt
        """

        log.debug("Finding key details from the Volume Keybag using the Personal Recovery Key")

        prk_uuid = bytes.fromhex(APFS_FV_PERSONAL_RECOVERY_KEY_UUID.replace("-", ""))

        for kl_entry in volume_keybag.mk_locker.kl_entries:
            if kl_entry.UUID == prk_uuid:
                log.debug("Found key details from the Volume Keybag!")
                return kl_entry.bag_data, kl_entry.iterations, kl_entry.kek_salt
        return None, None, None


    def get_wrapped_keybag(self, offset, block_count):
        """
        Return the wrapped keybag from the offsets specified in the Container Super Block
        """

        """Creates empty byte like object to hold our wrapped keybag"""
        block = b""

        """Logs our current offset to the offset of the wrapped keybag"""
        log.debug("Offset for the wrapped keybag is: " + str(offset))

        """Loops through reading blocks based on the amount of block the keybag has used based on keylocker_block_count"""
        for x in range(block_count):
            """Appends the block variables with the returned data"""
            block += self.ApfsVolume.container.get_block(offset)

            """Increases the current offset by the block size of the container"""
            offset += self.block_size

        """Returns the wrapped keybag"""
        return block

    def find_volume_keybag_details(self, container_keybag):
        """

        :param container_keybag:
        :return:
            Starting Offset to the Wrapped Volume Keybag
            Block Count of the Wrapped Volume Keybag
            UUID
        """
        for kl_entry in container_keybag.mk_locker.kl_entries:
            if kl_entry.KeyBag_Tags == KB_TAG_VOLUME_UNLOCK_RECORDS:
                # Returns the starting offset and the block count of the volume keybag if keylen is 16
                if kl_entry.key_keylen == 16:
                    log.debug(f"Found Wrapped Volume Keybag - Start Address: 0x{kl_entry.pr_start_paddr:X}" +
                                f" Block Count: {kl_entry.pr_block_count}")
                    return kl_entry.pr_start_paddr, kl_entry.pr_block_count, kl_entry.UUID


    def find_wrapped_vek(self, container_keybag):
        """

        :param container_keybag: The parsed container keybag
        :return: The wrapped VEK for the volume
        """

        log.debug("Searching for VEK now")

        volume_uuid = self.ApfsVolume.uuid
        volume_uuid = volume_uuid.replace("-", "")

        for kl_entry in container_keybag.mk_locker.kl_entries:
            if kl_entry.KeyBag_Tags == KB_TAG_VOLUME_KEY:

                # Converts the UUID in the unwrapped keybag entry to GUID like format for comparisons
                byte_uuid = kl_entry.UUID
                readable_UUID = convert_keybag_uuid_to_string(byte_uuid)
                if readable_UUID == volume_uuid:
                    log.debug("Found a UUID within the kl_entry with a Tag of two and a UUID that matches the "
                                   "Volume UUID we are trying to decrypt!")
                    return kl_entry.blob_header.bag_data

        return None

    def get_open_dir_uuid(self):
        open_dir_uuids = []
        for uuid in self.preboot_plist:
            if self.preboot_plist[uuid]['UserType'] == 'OpenDirectory':
                log.debug("Found Open Directory UUID from user: " + self.preboot_plist[uuid]['FullName'])
                log.debug("User's Open Directory UUID is: " + uuid)
                open_dir_uuids.append( (self.preboot_plist[uuid]['FullName'], uuid) )
        return open_dir_uuids

    def get_VEK_by_unwrapping_keys(self, user_password_key, wrapped_kek, wrapped_vek):
        '''Attempts to unwraps the KEK and then VEK. Returns VEK if successful else None'''
        try:
            unwrapped_kek = unwrap(wrapped_kek, user_password_key)
            vek = unwrap(wrapped_vek, unwrapped_kek)
            return vek
        except ValueError as ex: # Unwrap failed
            if str(ex).find("IV does not match") >= 0:
                pass # wrong password
            else:
                log.error('Error while unwrapping key ' + str(ex))
            return None

    def decrypter(self):

        # Uses the get_wrapped_keybag() function to get the wrapped keybag from the offsets defined in the
        # Conatiner Super Block
        # THIS IS STEP 1 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
        log.debug("Finding the Wrapped Keybag now")
        wrapped_container_keybag = self.get_wrapped_keybag(self.wrapped_keybag_offset, self.keylocker_block_count)

        # Decrypts the wrapped keybag
        # THIS IS STEP 2 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
        log.debug("Attempting to unwrap the Wrapped Keybag now")
        unwrapped_container_keybag = self.decrypt_keybag(wrapped_container_keybag, self.wrapped_keybag_offset, self.uuid)
        log.debug("Successfully unwrapped the Wrapped Keybag!")
        parsed_container_keybag = parse_vek_keybag(unwrapped_container_keybag)

        # Parses the unwrapped kb_locker object derived from the wrapped keybag into structures
        # THIS IS STEP 3 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
        log.debug("Parsing the unwrapped keybag now")
        wrapped_vek = self.find_wrapped_vek(parsed_container_keybag)

        # Returns if no UUID is found
        if wrapped_vek is None:
            log.error("COULD NOT FIND MATCHING UUID IN KEYBAG (for obtaining wrapped VEK). VOLUME CANNOT BE DECRYPTED!!")
            return

        # Finds the volumes keybag by looking at the unwrapped containers keybag with a tag of KB_TAG_VOLUME_UNLOCK_RECORDS
        # THIS IS STEP 4 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
        volume_keybag_start_addr, volume_keybag_block_count, volume_uuid = self.find_volume_keybag_details(parsed_container_keybag)
        wrapped_volume_keybag = self.get_wrapped_keybag(volume_keybag_start_addr, volume_keybag_block_count)

        # Decrypts the wrapped volume keybag
        # THIS IS STEP 5 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
        unwrapped_volume_keybag = self.decrypt_keybag(wrapped_volume_keybag, volume_keybag_start_addr, volume_uuid)

        # Parses the unwrapped volume kb_locker object derived from the wrapped keybag into structures
        parsed_volume_keybag = parse_volume_keybag(unwrapped_volume_keybag)


        """
        Find an entry in the volumeʼs keybag whose UUID matches the userʼs Open Directory UUID and whose tag is
        KB_TAG_VOLUME_UNLOCK_RECORDS. The key data for that entry is the wrapped KEK for this volume.

        THIS IS STEP 6 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION (find 3)
        """

        user_password_key = b''

        # Try supplied password as a recovery key first
        log.debug("Trying as Personal Recovery key to decrypt")
        wrapped_kek, iterations, salt = self.get_wrapped_key_from_prk(parsed_volume_keybag)
        if wrapped_kek:
            int_iterations = int.from_bytes(iterations, byteorder='big')
            # There may be a flag in the volume keybag to use SHA128 instead of SHA256, but that is unknown at the time
            user_password_key = hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt, int_iterations,
                                                    dklen=32)
            self.decryption_key = self.get_VEK_by_unwrapping_keys(user_password_key, wrapped_kek, wrapped_vek)

        # Try password if recovery key failed above
        if self.decryption_key is None:

            user_uuids = self.get_open_dir_uuid()
            if len(user_uuids) > 1:
                log.warning("There is more than one User Open Directory UUID. We will try for all users.")
            if len(user_uuids) == 0:
                log.error("There were no User Open Directory UUIDs found. Decryption cannot move forward")
                return

            for user, open_dir_uuid in user_uuids:
                log.info(f'Trying to decrypt encryption keys for user {user}')
                """
                Unwrap the KEK using the userʼs password, and then unwrap the VEK using the KEK, both according to the
                algorithm described in RFC 3394.

                THIS IS STEP 7 OF THE APFS ACCESSING ENCRYPTED OBJECTS DOCUMENTATION
                """
                wrapped_kek, iterations, salt = find_wrapped_kek_from_vol_keybag(parsed_volume_keybag,
                                                                                        open_dir_uuid)
                if wrapped_kek:
                    int_iterations = int.from_bytes(iterations, byteorder='big')

                    # There may be a flag in the volume keybag to use SHA128 instead of SHA256, but that is unknown at the time
                    user_password_key = hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt, int_iterations, dklen=32)
                    unwrapped_kek = unwrap(wrapped_kek, user_password_key)
                    unwrapped_vek = unwrap(wrapped_vek, unwrapped_kek)

                    self.decryption_key = self.get_VEK_by_unwrapping_keys(user_password_key, wrapped_kek, wrapped_vek)
                    if self.decryption_key:
                        return # on success
                else:
                    log.debug(f'Wrapped KEK was not present for user {user}')

        if not self.decryption_key:
            log.error('Could not decrypt with credentials provided!')
