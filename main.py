#!/usr/bin/env python3
import time

#============================
# The fancy manager
#============================
# Required python packages:
# - PyCrypto
#----------------------------
# Required 3rd party files:
# - make_cdn_cia
# - ctr-common-1.crt
# - ctr-common-1.key
#============================

#----------------------------
# Python Version Check
#----------------------------
import sys, codecs
if sys.version_info[0] != 3:
    invalid_python_version = u'Invalid Python Version: %s.%s.%s\nThis script has been tested with and requires Python3.' % (sys.version_info[0], sys.version_info[1], sys.version_info[2])
    print(invalid_python_version)
    raise SystemExit(0)
#----------------------------

from tkinter import *
from tkinter import messagebox, ttk
import argparse, binascii, io, os, queue, re, string, threading, urllib.request
import xml.etree.ElementTree as ET
import errno
#----------------------------
# argparse : Parse cli arguments
# binascii : Convert to/from bytes
# io       : convert non-files into "file-like objects"
# os       : Get basename of script and check file presence
# queue    : Queue for threading
# re       : Regexp search for ticket offset
# string   : Check if string is hexdecimal
# threading: Threading for url requests
# urllib   : Request url data
# xml      : Parse 3dsdb xml
# errno    : pmkdir
#----------------------------
# Todo:
# - Download App data
# - Download title metadata
# - Parse title metadata AFTER adding everything else to database (Nintendo CDN has correct values and supersedes everything from the community.)
# - Check decrypted key with PyCrypto and part of the downloaded app data, must be done prior to exporting anything (remove all invalid keys from sub_database for export)
# - Implement no hash
# - No download
# - Implement no build
# - Implement no 3ds
# - Implement no cia
# - Add gui mode
# - Add translation fanciness
#----------------------------


#====================#
#   Translate Text   #
#====================#
class AppText:
    def __init__(self):
        self.program_title        = u'[FabulousCDN]'
        self.force_gui_mode       = u'Forcing GUI mode, dropping all other arguments.'

        # File dialogue
        self.invalid_title_id     = u'Invalid Title Id: %s'
        self.invalid_title_key    = u'Invalid Title Key: %s'
        self.invalid_crypto_seed  = u'Invalid Crypto Seed: %s'
        self.invalid_common_key   = u'Invalid Common Key: %s'
        self.file_not_found       = u'File not found: %s doesn\'t exist.'
        self.no_database_found    = u'No entries in defined database.'
        self.incorrect_file_size  = u'Incorrect file size: %s'
        self.corrupted_ticket     = u'Corrupted ticket: %s doesn\'t match the ticket template.'
        self.imported_file        = u'%s entries found. %s imported.'
        self.exported_file        = u'%s entries written to %s.'
        self.failed_overwrite     = u'Failed to write: %s already exists.'

        # Web dialogue
        self.added_to_queue       = u'Request %s added to queue.'
        self.request_url_data     = u'Requesting data (%s): %d/%d attempts'
        self.request_url_suceed   = u'Retrieved data: %s'
        self.request_url_failed   = u'Failed to return data: %s'
        
        # -p --print title headers
        self.printing_database    = u'Printing current database...'
        self.h_fmt_title_name     = u'Title Name'
        self.h_fmt_title_id       = u'Title ID'
        self.h_fmt_dec_key        = u'Decrypted Key'
        self.h_fmt_enc_key        = u'Encrypted Key'
        self.h_fmt_crypto_seed    = u'Crypto Seed'
        self.h_fmt_region         = u'Rgn'
        self.h_fmt_size           = u'Size'
        self.h_fmt_type           = u'Type'
        self.h_fmt_serial         = u'Serial'
        self.h_fmt_publisher      = u'Publisher'
        self.h_fmt_common_key     = u'Com. Key'

        # Rom type
        self.sys_app              = u'Sys App'
        self.sys_data_archive     = u'Sys Data Archive'
        self.sys_applet           = u'Sys Applet'
        self.sys_module           = u'Sys Module'
        self.sys_firmware         = u'Sys Firmware'
        self.download_play        = u'Download Play'
        self.twl_sys_app          = u'TWL Sys App'
        self.twl_sys_data_archive = u'TWL Sys Data Archive'
        self.game_demo            = u'Game Demo'
        self.addon_dlc            = u'Addon DLC'
        self.eshop_title          = u'eShop/App'
        self.eshop_update         = u'eShop/App Update'
        
        self.not_implemented_yet  = u'Not Implemented Yet: %s\nThis feature has not been implemented yet. It will be added in time.'        


    def tid_index(self):
        tid_index = {
            '00040010': self.sys_app,
            '0004001B': self.sys_data_archive,
            '000400DB': self.sys_data_archive,
            '0004009B': self.sys_data_archive,
            '00040030': self.sys_applet,
            '00040130': self.sys_module,
            '00040138': self.sys_firmware,
            '00040001': self.download_play,
            '00048005': self.twl_sys_app,
            '0004800F': self.twl_sys_data_archive,
            '00040002': self.game_demo,
            '0004008C': self.addon_dlc
            }
        return tid_index
    def extended_tid_index(self):
        extended_tid_index = self.tid_index()
        extended_tid_index.update({
            '00040000': self.eshop_title,
            '0004000E': self.eshop_update
            })
        return extended_tid_index


#====================#
#   Backend Logic    #
#====================#
class webdata_handler:
    def __init__(self, t_handler):
        self.log = t_handler.log
        ## Start generating queue for multithreading
        self.queue = queue.Queue()
        self.main_thread = threading.currentThread()
        self.queue_results = []
    def request_queue(self, type, arg):
        self.log.add(AppText().added_to_queue % type)
        self.queue.put((type, arg, self.queue_results))
        t = threading.Thread(target=self.worker_thread)
        t.setDaemon(True)
        t.start()
    def join_queue(self):
        # Call to wait for queue to finish before continuing
        for thread in threading.enumerate():
            if thread is self.main_thread:
                continue
            thread.join()
    def worker_thread(self):
        thread = threading.currentThread()
        type, arg, queue_results = self.queue.get()
        if type == 'dec': result = self.pull_nfshost(type=type, tmp=arg)
        elif type == 'enc': result = self.pull_nfshost(type=type, tmp=arg)
        elif type == 'xml': result = self.pull_community_xml(tmp=arg)
        elif type == 'tmd': result = self.pull_tmd(arg)
        elif type == 'meta': result = self.pull_title_metadata(arg)
        queue_results.append([type, arg, result])
        self.queue.task_done()
        return

    def pull_nfshost(self, type=None, tmp=None):
        url = 'http://3ds.nfshost.com/download'
        if type == 'enc': url = '%s%s' % (url, type)
        url_data = self.request_url(url)
        if not url_data: return
        bytes = io.BytesIO(url_data.read())
        t_handler.load_bin(url, type=type, direct=bytes)
        bytes.seek(0, os.SEEK_SET)
        if tmp != 'tmp':
            pmkdir('data')
            with open('data/%sTitleKeys.bin' % type, 'wb') as file_handler:
                file_handler.write(bytes.read())
                file_handler.close()
        return bytes
    def pull_community_xml(self, tmp=None):
        url = 'http://3dsdb.com/xml.php'
        url_data = self.request_url(url)
        if not url_data: return
        bytes = io.BytesIO(url_data.read())
        t_handler.load_bin(url, type='xml', direct=bytes)
        bytes.seek(0, os.SEEK_SET)
        if tmp != 'tmp':
            pmkdir('data')
            with open('data/3dsreleases.xml', 'wb') as file_handler:
                file_handler.write(bytes.read())
                file_handler.close()
        return bytes
    def pull_title_metadata(self, title_id):
        self.log.add(AppText().not_implemented_yet % 'pull title metadata', err=-1)  ##FIXIT
    def pull_tmd(self, title_id):
        url = 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/%s/tmd' % title_id
        url_data = self.request_url(url)
        if not url_data: return
        bytes = io.BytesIO(url_data.read())
        return bytes
    def request_url(self, url):
        n_of_attempts = 3
        error = False
        for attempt in range(n_of_attempts):
            try:
                if(attempt < n_of_attempts):
                    self.log.add(AppText().request_url_data % (url, attempt+1, n_of_attempts))
                    url_data = urllib.request.urlopen(url)
            except urllib.URLError as e:
                error = True
                continue
            error = False
            break
        if error: return self.log.add(AppText().request_url_failed % url, err=-1)
        self.log.add(AppText().request_url_suceed % url)
        return url_data


class title_database_handler: 
    def __init__(self):
        self.title_database = {}
        self.log = logging_handler()
        self.w_handler = webdata_handler(self)
        # Ticket template
        self.ticket_template = '00010004d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC00000000000000000000000000AAAAAAAAAAAAAAAA00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        self.ticket_magic    = '00010004919ebe464ad0f552cd1b72e7884910cf55a9f02e50789641d896683dc005bd0aea87079d8ac284c675065f74c8bf37c88044409502a022980bb8ad48383f6d28a79de39626ccb2b22a0f19e41032f094b39ff0133146dec8f6c1a9d55cd28d9e1c47b3d11f4f5426c2c780135a2775d3ca679bc7e834f0e0fb58e68860a71330fc95791793c8fba935a7a6908f229dee2a0ca6b9b23b12d495a6fe19d0d72648216878605a66538dbf376899905d3445fc5c727a0e13e0e2c8971c9cfa6c60678875732a4e75523d2f562f12aabd1573bf06c94054aefa81a71417af9a4a066d0ffc5ad64bab28b1ff60661f4437d49e1e0d9412eb4bcacf4cfd6a3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137a0894ad505bb6c67e2e5bdd6a3bec43d910c772e9cc290da58588b77dcc11680bb3e29f4eabbb26e98c2601985c041bb14378e689181aad770568e928a2b98167ee3e10d072beef1fa22fa2aa3e13f11e1836a92a4281ef70aaf4e462998221c6fbb9bdd017e6ac590494e9cea9859ceb2d2a4c1766f2c33912c58f14a803e36fccdcccdc13fd7ae77c7a78d997e6acc35557e0d3e9eb64b43c92f4c50d67a602deb391b06661cd32880bd64912af1cbcb7162a06f02565d3b0ece4fcecddae8a4934db8ee67f3017986221155d131c6c3f09ab1945c206ac70c942b36f49a1183bcd78b6e4b47c6c5cac0f8d62f897c6953dd12f28b70c5b7df751819a9834652625000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010003704138efbbbda16a987dd901326d1c9459484c88a2861b91a312587ae70ef6237ec50e1032dc39dde89a96a8e859d76a98a6e7e36a0cfe352ca893058234ff833fcb3b03811e9f0dc0d9a52f8045b4b2f9411b67a51c44b5ef8ce77bd6d56ba75734a1856de6d4bed6d3a242c7c8791b3422375e5c779abf072f7695efa0f75bcb83789fc30e3fe4cc8392207840638949c7f688565f649b74d63d8d58ffadda571e9554426b1318fc468983d4c8a5628b06b6fc5d507c13e7a18ac1511eb6d62ea5448f83501447a9afb3ecc2903c9dd52f922ac9acdbef58c6021848d96e208732d3d1d9d9ea440d91621c7a99db8843c59c1f2e2c7d9b577d512c166d6f7e1aad4a774a37447e78fe2021e14a95d112a068ada019f463c7a55685aabb6888b9246483d18b9c806f474918331782344a4b8531334b26303263d9d2eb4f4bb99602b352f6ae4046c69a5e7e8e4a18ef9bc0a2ded61310417012fd824cc116cfb7c4c1f7ec7177a17446cbde96f3edd88fcd052f0b888a45fdaf2b631354f40d16e5fa9c2c4eda98e798d15e6046dc5363f3096b2c607a9d8dd55b1502a6ac7d3cc8d8c575998e7d796910c804c495235057e91ecd2637c9c1845151ac6b9a0490ae3ec6f47740a0db0ba36d075956cee7354ea3e9a4f2720b26550c7d394324bc0cb7e9317d8a8661f42191ff10b08256ce3fd25b745e5194906b4d61cb4c2e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007be8ef6cb279c9e2eee121c6eaf44ff639f88f078b4b77ed9f9560b0358281b50e55ab721115a177703c7a30fe3ae9ef1c60bc1d974676b23a68cc04b198525bc968f11de2db50e4d9e7f071e562dae2092233e9d363f61dd7c19ff3a4a91e8f6553d471dd7b84b9f1b8ce7335f0f5540563a1eab83963e09be901011f99546361287020e9cc0dab487f140d6626a1836d27111f2068de4772149151cf69c61ba60ef9d949a0f71f5499f2d39ad28c7005348293c431ffbd33f6bca60dc7195ea2bcc56d200baf6d06d09c41db8de9c720154ca4832b69c08c69cd3b073a0063602f462d338061a5ea6c915cd5623579c3eb64ce44ef586d14baaa8834019b3eebeed3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    def load_bin(self, file_in, type=None, direct=None):
        ## If direct, it's from the web, thus skip all checks and "file_handler" == "direct", "file_in" == "url"
        if not direct:
            # Check if file exists
            if not os.path.isfile(file_in):
                return self.log.add(AppText().file_not_found % file_in, err=-1)
            # Check if size is correct
            if type in ['dec', 'enc', 'seed', 'tik']: size_check = (os.path.getsize(file_in) % 32) - 16
            elif type == 'xml': 
                if os.path.getsize(file_in) > 0: size_check = 0
                else: size_check = 1
            else: size_check = os.path.getsize(file_in) - 37221888
            if size_check != 0:
                return self.log.add(AppText().incorrect_file_size % file_in, err=-1)
            file_handler = open(file_in, 'rb')
        else:
            file_handler = direct
        # Import file data to database
        n_entries = 0
        if type in ['dec', 'enc', 'seed']:
            # decTitleKey, encTitleKey, seeddb
            # Read number of entries
            n_entries = len(file_handler.read()) / 32
            file_handler.seek(16, os.SEEK_SET)
            for i in range(int(n_entries)):
                com_key = u'00000000'
                if type in ['dec', 'enc']:
                    c_key = file_handler.read(4)
                    file_handler.seek(4, os.SEEK_CUR)
                    title_id = file_handler.read(8)
                    key = file_handler.read(16)
                    c_key = binascii.hexlify(c_key).decode('utf-8')
                    if com_key == c_key: c_key = None
                elif type == 'seed':
                    title_id = file_handler.read(8)
                    key = file_handler.read(16)
                    file_handler.seek(8, os.SEEK_CUR)
                title_id = binascii.hexlify(title_id).decode('utf-8')
                key = binascii.hexlify(key).decode('utf-8')
                # Add entry to database
                if type == 'dec':
                    self.add_entry(title_id, decrypted_title_key=key, common_key=c_key)
                elif type == 'enc':
                    self.add_entry(title_id, encrypted_title_key=key, common_key=c_key)
                elif type == 'seed':
                    title_id = ''.join(reversed([title_id[i:i+2] for i in range(0, len(title_id), 2)]))
                    self.add_entry(title_id, crypto_seed=key)
        elif type == 'tik':
            tmp_ticket_head = binascii.hexlify(file_handler.read(447)).decode('utf-8')
            key = binascii.hexlify(file_handler.read(16)).decode('utf-8')
            file_handler.seek(13, os.SEEK_CUR)
            title_id = binascii.hexlify(file_handler.read(8)).decode('utf-8')
            tmp_ticket_tail = binascii.hexlify(file_handler.read(364)).decode('utf-8')
            if tmp_ticket_head != self.ticket_template[:894]: return self.log.add(AppText().corrupted_ticket % file_in, err=-1)
            if tmp_ticket_tail != self.ticket_template[976:1696]: return self.log.add(AppText().corrupted_ticket % file_in, err=-1)
            n_entries += 1
            self.add_entry(title_id, encrypted_title_key=key)
        elif type == 'xml':
            tree = ET.ElementTree(file=file_handler)
            root = tree.getroot()
            n_entries = len(root)
            for i in range(n_entries):
                e=root[i]
                database_index = e[0].text
                title_name     = e[1].text
                publisher      = e[2].text
                region         = e[3].text
                language       = e[4].text
                release_group  = e[5].text
                image_size     = e[6].text
                serial         = e[7].text
                title_id       = e[8].text
                image_crc      = e[9].text
                filename       = e[10].text
                release_name   = e[11].text
                trimmed_size   = e[12].text
                firmware       = e[13].text
                type           = e[14].text    ##Drop 3dsdb typing for tid_high typing
                card           = e[15].text
                self.add_entry(title_id, database_index=database_index, title_name=title_name, publisher=publisher, region=region, language=language, release_group=release_group, image_size=image_size, serial=serial, image_crc=image_crc, filename=filename, release_name=release_name, trimmed_size=trimmed_size, firmware=firmware, type=type, card=card)
        else:
            # ticket.db
            tickets = file_handler.read()
            # This check can fail on other DB files (since 'Root-CA' can appear in them, but not necessarily mean there are tickets).
            ticket_offsets = [match.start() for match in re.finditer(b'Root-CA00000003-XS0000000c', tickets)]
            tickets = bytearray(tickets)
            for offset in ticket_offsets:
                enc_title_key    = tickets[offset+0x7F:offset+0x8F]
                title_id         = tickets[offset+0x9C:offset+0xA4]
                common_key_index = tickets[offset+0xB1]  # common_key_index is worthless for what this script wants to do, but extra checks are always nice
                # Check if potentially valid ticket, offset+0x7C is always 0x1.
                if tickets[offset+0x7C] != 0x1: continue
                if common_key_index > 5: continue
                # Add entry to database
                n_entries += 1
                title_id = binascii.hexlify(title_id).decode('utf-8')
                key = binascii.hexlify(enc_title_key).decode('utf-8')
                self.add_entry(title_id, encrypted_title_key=key)
        self.log.add(AppText().imported_file % (int(n_entries), file_in))
    def check_decrypted_title_key(self, title_id):
        self.log.add(AppText().not_implemented_yet % 'check decrypted title key')
    def write_bin(self, overwrite=False, database=None, out_dir=None, title_id=None, file_out=None, type=None):
        # Create output filename and path
        output = ''
        if out_dir:
            pmkdir(out_dir)
            output += out_dir+'/'
        if title_id:
            pmkdir(output+title_id)
            output += title_id+'/'
        if file_out:
            output += file_out
        elif type == 'dec':
            output += 'decTitleKey.bin'
        elif type == 'enc':
            output += 'encTitleKey.bin'
        elif type == 'seed':
            output += 'seeddb.bin'
        elif type == 'tik':
            output += '%s.tik' % title_id
        elif type == 'xml':
            output += '3dsreleases.xml'
        if os.path.isfile(output) and overwrite == False: return self.log.add(AppText().failed_overwrite % output, err=-1)
        # Generate entries in database to file
        entry_list = ''
        for title_id in database:
            if type in ['dec', 'enc']:
                if not database[title_id]['dec_key'] and type == 'dec': self.log.add('Skipping %s, missing decrypted key.' % title_id ,err=-1); continue  ##FIXIT
                elif database[title_id]['dec_key'] and type == 'dec': sect4 = database[title_id]['dec_key']
                if not database[title_id]['enc_key'] and type == 'enc': self.log.add('Skipping %s, missing encrypted key.' % title_id ,err=-1); continue  ##FIXIT
                elif database[title_id]['enc_key'] and type == 'enc': sect4 = database[title_id]['enc_key']
                reserved = ''.rjust(8, 'F')
                if not database[title_id]['common_key']: common_key = ''.rjust(8, '0')
                else: common_key = database[title_id]['common_key']
                string_order = '{0}{1}{2}{3}'
                sect1, sect2, sect3 = (common_key, reserved, title_id)
            elif type == 'seed':
                if not database[title_id]['crypto_seed']: self.log.add('Skipping %s, missing crypto seed.' % title_id ,err=-1); continue  ##FIXIT
                reserved  = ''.rjust(8, '0')
                # Reverse title_id
                rev_title_id = ''.join(reversed([title_id[i:i+2] for i in range(0, len(title_id), 2)]))
                string_order = '{0}{1}{2}{2}'
                sect1, sect2, sect3, sect4 = (rev_title_id, database[title_id]['crypto_seed'], reserved, None)
            elif type == 'tik':
                if not database[title_id]['enc_key']: self.log.add('Skipping %s, missing encrypted key.' % title_id ,err=-1); continue  ##FIXIT
                self.w_handler.request_queue('tmd', title_id)
                string_order = '{0}{1}{2}{3}'
                ticket_template = io.StringIO(self.ticket_template[:])
                tik_head = 894
                sect1 = ticket_template.read(tik_head)
                ## Wait for result in w_handler
                self.w_handler.join_queue()
                for result in self.w_handler.queue_results:
                    if title_id in result and result[2]:
                        tmd = result[2]; break
                tmd.seek(476)
                tmd_bytes = binascii.hexlify(tmd.read(2)).decode('utf-8')
                sect2 = '{0}{3:0<26.26}{1}{3:0<4.4}{2}'.format(database[title_id]['enc_key'], title_id, tmd_bytes,''.rjust(2, str(0)))
                ticket_template.seek(tik_head+82)
                sect3 = ticket_template.read()
                sect4 = self.ticket_magic[:]
            elif type == 'xml':
                self.log.add(AppText().not_implemented_yet, err=-1)  ##FIXIT
            entry = string_order.format(sect1, sect2, sect3, sect4)
            entry_list += entry
        # Add entries if entry_list has at least one entry
        if entry_list:
            with open(output, 'wb') as file_handler:
                if type in ['enc', 'dec', 'seed']:
                    n_entries = int(len(entry_list) / 64)
                    entry_count = hex(n_entries).split('x')[1].zfill(8)
                    entry_count = '{0}{0}{0}{1}'.format(reserved,entry_count)
                    entry_count = ''.join(reversed([entry_count[i:i+2] for i in range(0, len(entry_count), 2)]))
                    file_handler.write(binascii.unhexlify(entry_count))
                elif type == 'tik':
                    if not database[title_id]['enc_key']: n_entries = 0
                    else: n_entries = 1
                elif type == 'xml':
                    # Write xml header 
                    self.log.add(AppText().not_implemented_yet, err=-1)  ##FIXIT
                file_handler.write(binascii.unhexlify(entry_list))
                file_handler.close()
        self.log.add(AppText().exported_file % (n_entries, output))
    def add_entry(self, title_id, database_index=None, title_name=None, publisher=None, region=None, language=None, release_group=None, image_size=None, serial=None, image_crc=None, filename=None, release_name=None, trimmed_size=None, firmware=None, type=None, card=None, decrypted_title_key=None, encrypted_title_key=None, crypto_seed=None, common_key=None):
        title_id = str(title_id).upper()
        if title_id in self.title_database.keys():
            # If missing data isn't passed to entry, use previous values.
            if not database_index: database_index = self.title_database[title_id]['database_index']
            if not title_name    : title_name     = self.title_database[title_id]['title_name']
            if not publisher     : publisher      = self.title_database[title_id]['publisher']
            if not region        : region         = self.title_database[title_id]['region']
            if not language      : language       = self.title_database[title_id]['language']
            if not release_group : release_group  = self.title_database[title_id]['release_group']
            if not image_size    : image_size     = self.title_database[title_id]['image_size']
            if not serial        : serial         = self.title_database[title_id]['serial']
            if not image_crc     : image_crc      = self.title_database[title_id]['image_crc']
            if not filename      : filename       = self.title_database[title_id]['filename']
            if not release_name  : release_name   = self.title_database[title_id]['release_name']
            if not trimmed_size  : trimmed_size   = self.title_database[title_id]['trimmed_size']
            if not firmware      : firmware       = self.title_database[title_id]['firmware']
            if not type          : type           = self.title_database[title_id]['type']
            if not card          : card           = self.title_database[title_id]['card']
            if not decrypted_title_key: decrypted_title_key = self.title_database[title_id]['dec_key']
            if not encrypted_title_key: encrypted_title_key = self.title_database[title_id]['enc_key']
            if not crypto_seed        : crypto_seed         = self.title_database[title_id]['crypto_seed']
            if not common_key         : common_key          = self.title_database[title_id]['common_key']
            # If missing data IS passed to entry, standardize all inputs to capitals.
            #if database_index: database_index = database_index      ## Unneeded line   ##FIXIT
            #if title_name    : title_name     = title_name          ## Unneeded line
            #if publisher     : publisher      = publisher           ## Unneeded line
            if region        : region         = region.upper()
            if language      : language       = language.upper()
            #if release_group : release_group  = release_group       ## Unneeded line
            if image_size    : image_size     = image_size.upper()
            if serial        : serial         = serial.upper()
            if image_crc     : image_crc      = image_crc.upper()    ## Not useful
            #if filename      : filename       = filename            ## Unneeded line
            #if release_name  : release_name   = release_name        ## Unneeded line
            if trimmed_size  : trimmed_size   = trimmed_size.upper() ## Not useful
            #if firmware      : firmware       = firmware            ## Unneeded line
            if type          : type           = type.upper()
            if card          : card           = card.upper()         ## Not useful
            if decrypted_title_key: decrypted_title_key = decrypted_title_key.upper()
            if encrypted_title_key: encrypted_title_key = encrypted_title_key.upper()
            if crypto_seed        : crypto_seed         = crypto_seed.upper()
            if common_key         : common_key          = common_key.upper()
        self.title_database.update({
            title_id: {
                'database_index' : database_index,    #Useless metadata
                'title_name'     : title_name,
                'publisher'      : publisher,
                'region'         : region,
                'language'       : language,
                'release_group'  : release_group,     #Useless metadata
                'image_size'     : image_size,
                'serial'         : serial,
                'title_id'       : title_id,
                'image_crc'      : image_crc,         #Useless metadata
                'filename'       : filename,          #Useless metadata
                'release_name'   : release_name,      #Useless metadata
                'trimmed_size'   : trimmed_size,      #Useless metadata
                'firmware'       : firmware,          #Useless metadata
                'type'           : str(title_id)[:8], ##Drop 3dsdb typing for tid_high typing
                'card'           : card,              #Useless metadata
                'dec_key'        : decrypted_title_key,
                'enc_key'        : encrypted_title_key,
                'crypto_seed'    : crypto_seed,
                'common_key'     : common_key
                }
            })
        #self.log.add('Updated title database entry: %s' % self.title_database[title_id])


#====================#
# Frontend CLI Logic #
#====================#
class CliName:
    def __init__(self, t_handler):
        self.log = t_handler.log
        parser = argparse.ArgumentParser()
        ## store_true: default is false, true when argument present
        parser.add_argument('-g',   '--gui',                        action='store_true',  dest='gui_mode',                                 help='Forces gui mode and drops all other arguments')
        parser.add_argument('-v',   '--verbose',                    action='store_true',  dest='verbose',                                  help='Prints out a simple log of script process and errors.')
        parser.add_argument('-i',   '--info',                       action='store_true',  dest='info',                                     help='Displays title metadata')
        parser.add_argument('-p',   '--print',           nargs='?', action='store',       dest='print_format',    const='default',         help='Prints out a formatted database listing of all loaded files')
        parser.add_argument('-t',   '--print_title',                action='store_false', dest='title_header',                             help='Prepends listing with a title header with specified formatting')
        parser.add_argument('-d',   '--pull',            nargs='?', action='store',       dest='pull_data',       const='local',           help='Parses local data folder (default) or the web for information. Available input: local, web, tmp')
        parser.add_argument('-tid', '--title_id',                   action='store',       dest='title_id',                                 help='Title ID of the content you want to download')
        parser.add_argument('-dk',  '--dec_key',                    action='store',       dest='dec_title_key',                            help='Add a decrypted title key for the Title ID')
        parser.add_argument('-ek',  '--enc_key',                    action='store',       dest='enc_title_key',                            help='Add an encrypted title key for the Title ID')
        parser.add_argument('-cs',  '--crypto',                     action='store',       dest='crypto_seed',                              help='Add a crypto seed for the Title ID')
        parser.add_argument('-ck',  '--com_key',                    action='store',       dest='common_key',                               help='Add a common key for the Title ID')
        parser.add_argument('-di',  '--decTitleKey_in',  nargs='?', action='store',       dest='decTitleKey_in',  const='decTitleKey.bin', help='Parses decTitleKey.bin formatted files for decrypted title keys')
        parser.add_argument('-ei',  '--encTitleKey_in',  nargs='?', action='store',       dest='encTitleKey_in',  const='encTitleKey.bin', help='Parses encTitleKey.bin formatted files for encrypted title keys')
        parser.add_argument('-si',  '--seeddb_in',       nargs='?', action='store',       dest='seeddb_in',       const='seeddb.bin',      help='Parses seeddb.bin for 9.6+ NCCH crypto keys')
        parser.add_argument('-xi',  '--xml_in',          nargs='?', action='store',       dest='xml_in',          const='3dsreleases.xml', help='Parses 3dsreleases.xml for metadata')
        parser.add_argument('-tik', '--ticket_in',                  action='store',       dest='ticket_in',                                help='Parses ticket.tik formatted files for encrypted title key')
        parser.add_argument('-ti',  '--ticketdb_in',     nargs='?', action='store',       dest='ticketdb_in',     const='ticket.db',       help='Parses ticket.db formatted files for encrypted title keys')
        parser.add_argument('-do',  '--decTitleKey_out', nargs='?', action='store',       dest='decTitleKey_out', const='decTitleKey.bin', help='Outputs concatenated inputs to decTitleKey.bin')
        parser.add_argument('-eo',  '--encTitleKey_out', nargs='?', action='store',       dest='encTitleKey_out', const='encTitleKey.bin', help='Outputs concatenated inputs to encTitleKey.bin')
        parser.add_argument('-so',  '--seeddb_out',      nargs='?', action='store',       dest='seeddb_out',      const='seeddb.bin',      help='Outputs concatenated inputs to seeddb.bin')
        parser.add_argument('-to',  '--ticket_out',                 action='store_true',  dest='ticket_out',                               help='Outputs inputs to individual tickets <title_id>/<title_id>.tik')
        parser.add_argument('-f',   '--force',                      action='store_true',  dest='overwrite',                                help='Force overwrite files')
        parser.add_argument('-o',   '--out_dir',         nargs='?', action='store',       dest='output_dir',      const='output',          help='Custom output directory to store output')
        parser.add_argument('-nh',  '--no_hash',                    action='store_true',  dest='no_hash',                                  help='Skip hash check')
        parser.add_argument('-nd',  '--no_download',                action='store_true',  dest='no_download',                              help='Don\'t download title')
        parser.add_argument('-nb',  '--no_build',                   action='store_true',  dest='no_build',                                 help='Don\'t build .3ds or .cia file')
        parser.add_argument('-n3',  '--no_3ds',                     action='store_true',  dest='no_3ds',                                   help='Don\'t build .3ds file')
        parser.add_argument('-nc',  '--no_cia',                     action='store_true',  dest='no_cia',                                   help='Don\'t build .cia file')
        self.args = parser.parse_args()
    def parse_args(self):
        args = self.args
        # Force GUI mode if no arguments or --gui flag set
        if not any([args.title_id, args.dec_title_key, args.enc_title_key, args.pull_data, args.decTitleKey_in, args.encTitleKey_in, args.seeddb_in, args.ticket_in, args.ticketdb_in, args.filter]) or args.gui_mode:
            self.log.add(AppText().force_gui_mode)
            self.args.gui_mode = True
            return
        # Check for verbose
        if args.verbose:
            self.log.verbose = True
        # Check title id 
        if args.title_id:
            args.title_id = args.title_id.upper()
            if (len(args.title_id) is 16) and all(character in string.hexdigits for character in args.title_id):
                t_handler.add_entry(args.title_id)
                #self.log.add('Added Title ID: %s' % args.title_id)  ##FIXIT
            else:
                self.log.add(AppText().invalid_title_id % args.title_id, err=-1)
            # Check decrypted title key
            if args.dec_title_key:
                if (len(args.dec_title_key) is 32) and all(character in string.hexdigits for character in args.dec_title_key):
                    t_handler.add_entry(args.title_id, decrypted_title_key=args.dec_title_key)
                    #self.log.add('Added decrypted title key: %s' % args.dec_title_key)  ##FIXIT
                else:
                    self.log.add(AppText().invalid_title_key % args.dec_title_key, err=-1)
            # Check encrypted title key
            if args.enc_title_key:
                if (len(args.enc_title_key) is 32) and all(character in string.hexdigits for character in args.enc_title_key):
                    t_handler.add_entry(args.title_id, encrypted_title_key=args.enc_title_key)
                    #self.log.add('Added encrypted title key: %s' % args.enc_title_key)  ##FIXIT
                else:
                    self.log.add(AppText().invalid_title_key % args.enc_title_key, err=-1)
            # Check crypto seed
            if args.crypto_seed:
                if (len(args.enc_title_key) is 32) and all(character in string.hexdigits for character in args.enc_title_key):
                    t_handler.add_entry(args.title_id, crypto_seed=args.crypto_seed)
                    #self.log.add('Added crypto seed: %s' % args.crypto_seed)  ##FIXIT
                else:
                    self.log.add(AppText().invalid_crypto_seed % args.crypto_seed, err=-1)
            # Check common key
            if args.common_key:
                if (len(args.enc_title_key) is 8) and all(character in string.hexdigits for character in args.enc_title_key):
                    t_handler.add_entry(args.title_id, common_key=args.common_key)
                    #self.log.add('Added common key: %s' % args.common_key)  ##FIXIT
                else:
                    self.log.add(AppText().invalid_common_key % args.common_key, err=-1)
        # Check decTitleKey.bin
        if args.decTitleKey_in:
            for file in args.decTitleKey_in.split(','):
                t_handler.load_bin(file, type='dec')
        # Check encTitleKey.bin
        if args.encTitleKey_in:
            for file in args.encTitleKey_in.split(','):
                t_handler.load_bin(file, type='enc')
        # Check seeddb.bin
        if args.seeddb_in:
            for file in args.seeddb_in.split(','):
                t_handler.load_bin(file, type='seed')
        # Check 3dsreleases.xml
        if args.xml_in:
            for file in args.xml_in.split(','):
                t_handler.load_bin(file, type='xml')
        # Check ticket.tik
        if args.ticket_in:
            for file in args.ticket_in.split(','):
                t_handler.load_bin(file, type='tik')
        # Check ticket.db
        if args.ticketdb_in:
            for file in args.ticketdb_in.split(','):
                t_handler.load_bin(file)
        # Check from local or web
        if args.pull_data:
            if args.pull_data == 'local':
                t_handler.load_bin('data/decTitleKeys.bin', type='dec')
                t_handler.load_bin('data/encTitleKeys.bin', type='enc')
                t_handler.load_bin('data/seeddb.bin', type='seed')
                t_handler.load_bin('data/3dsreleases.xml', type='xml')
                t_handler.load_bin('data/ticket.db')
            elif args.pull_data in ['web', 'tmp']:
                t_handler.w_handler.request_queue('enc', args.pull_data)
                t_handler.w_handler.request_queue('dec', args.pull_data)
                t_handler.w_handler.request_queue('xml', args.pull_data)
                t_handler.w_handler.join_queue()
                
        # Set sub_database after concatenating everything into a single title_database
        sub_database = t_handler.title_database
        # Modify sub_database through filter
        if args.filter:
            filters = [filter.upper() for filter in args.filter.split(',')]
            self.log.add("Filtering for %s" % filters) ##FIXIT
            if not sub_database: self.log.add(AppText().no_database_found, err=-1)
            tmp_database = {}
            for title_id in sub_database:
                append = 0
                if sub_database[title_id]['region'] in filters: append+=1
                if 'decrypted' in filters and sub_database[title_id]['dec_key'] != None: append+=1
                if 'encrypted' in filters and sub_database[title_id]['enc_key'] != None: append+=1
                if 'crypto' in filters and sub_database[title_id]['crypto_seed'] != None: append+=1
                if 'title' in filters and sub_database[title_id]['title_name'] != None: append+=1
                if 'update' in filters and sub_database[title_id]['type'] == '0004000E': append+=1
                if 'dlc' in filters and sub_database[title_id]['type'] == '0004008C': append+=1
                if 'app' in filters and sub_database[title_id]['type'] == '00040000': append+=1
                if 'dlplay' in filters and sub_database[title_id]['type'] == '00040001': append+=1
                if 'demo' in filters and sub_database[title_id]['type'] == '00040002': append+=1
                if 'sysapp' in filters and sub_database[title_id]['type'] == '00040010': append+=1
                if 'sysapplet' in filters and sub_database[title_id]['type'] == '00040030': append+=1
                if 'sysmod' in filters and sub_database[title_id]['type'] == '00040130': append+=1
                if 'sysfirm' in filters and sub_database[title_id]['type'] == '00040138': append+=1
                if 'sysarc' in filters and sub_database[title_id]['type'] in ['0004001B', '000400DB', '0004009B']: append+=1
                if 'twlsys' in filters and sub_database[title_id]['type'] == '00048005': append+=1
                if 'twlarc' in filters and sub_database[title_id]['type'] == '0004800F': append+=1
                if title_id in filters: append+=1
                if append >= len(filters): tmp_database.update({title_id: sub_database[title_id]})
            sub_database = tmp_database
            
        # Export decTitleKey.bin
        if args.decTitleKey_out:
            if args.dec_title_key:
                sub_database = {args.title_id: t_handler.title_database[args.title_id]}
            t_handler.write_bin(overwrite=args.overwrite, database=sub_database, out_dir=args.output_dir, title_id=args.title_id, file_out=args.decTitleKey_out, type='dec')
        # Export encTitleKey.bin
        if args.encTitleKey_out:
            if args.enc_title_key:
                sub_database = {args.title_id: t_handler.title_database[args.title_id]}
            t_handler.write_bin(overwrite=args.overwrite, database=sub_database, out_dir=args.output_dir, title_id=args.title_id, file_out=args.encTitleKey_out, type='enc')
        # Export seeddb.bin
        if args.seeddb_out:
            if args.title_id:
                sub_database = {args.title_id: t_handler.title_database[args.title_id]}
            t_handler.write_bin(overwrite=args.overwrite, database=sub_database, out_dir=args.output_dir, title_id=args.title_id, file_out=args.seeddb_out, type='seed')
        # Export <title_id>.tik
        if args.ticket_out:
            if args.title_id:
                sub_database = {args.title_id: t_handler.title_database[args.title_id]}
                t_handler.write_bin(overwrite=args.overwrite, database=sub_database, out_dir=args.output_dir, title_id=args.title_id, file_out='%s.tik' % args.title_id, type='tik')
            else:
                for tid in sub_database:
                    super_sub_database = {tid: t_handler.title_database[tid]}
                    t_handler.write_bin(overwrite=args.overwrite, database=super_sub_database, out_dir=args.output_dir, title_id=tid, type='tik')
        
        # Print out database
        if args.print_format:
            title_name_limit  = 36
            title_id_limit    = 16
            dec_key_limit     = 32
            enc_key_limit     = 32
            crypto_seed_limit = 32
            region_limit      = 3
            size_limit        = 4
            type_limit        = 20
            serial_limit      = 10
            publisher_limit   = 20
            common_key_limit  = 8
            if args.print_format != 'default':
                format_string = args.print_format
            else:
                format_string = '| %title_name | %title_id | %serial | %region | %size | %type | %publisher | %dec_key | %enc_key | %crypto_seed | %common_key |'
            # Replace string to known format
            format_string = format_string.replace('%title_name',  '{{0: <{0}.{0}}}'.format(title_name_limit))
            format_string = format_string.replace('%title_id',    '{{1: ^{0}.{0}}}'.format(title_id_limit))
            format_string = format_string.replace('%dec_key',     '{{2: ^{0}.{0}}}'.format(dec_key_limit))
            format_string = format_string.replace('%enc_key',     '{{3: ^{0}.{0}}}'.format(enc_key_limit))
            format_string = format_string.replace('%crypto_seed', '{{4: ^{0}.{0}}}'.format(crypto_seed_limit))
            format_string = format_string.replace('%region',      '{{5: ^{0}.{0}}}'.format(region_limit))
            format_string = format_string.replace('%size',        '{{6: ^{0}.{0}}}'.format(size_limit))
            format_string = format_string.replace('%type',        '{{7: ^{0}.{0}}}'.format(type_limit))
            format_string = format_string.replace('%serial',      '{{8: ^{0}.{0}}}'.format(serial_limit))
            format_string = format_string.replace('%publisher',   '{{9: ^{0}.{0}}}'.format(publisher_limit))
            format_string = format_string.replace('%common_key',  '{{10: ^{0}.{0}}}'.format(common_key_limit))
            # Add title header
            if args.title_header:
                head_line = format_string.format(
                    AppText().h_fmt_title_name,
                    AppText().h_fmt_title_id,
                    AppText().h_fmt_dec_key,
                    AppText().h_fmt_enc_key,
                    AppText().h_fmt_crypto_seed,
                    AppText().h_fmt_region,
                    AppText().h_fmt_size,
                    AppText().h_fmt_type,
                    AppText().h_fmt_serial,
                    AppText().h_fmt_publisher,
                    AppText().h_fmt_common_key)
                split_line = re.sub(r'[^\{0-9:<^>.\}]', '-', format_string)
                split_line = split_line.format('', '', '', '', '', '', '', '', '', '', '')
                split_line = '{1}{0}{1}'.format(split_line[1:-1], '|')
                self.log.add(AppText().printing_database)
                print(split_line)
                print(head_line)
                print(split_line)
            tid_index = AppText().extended_tid_index()
            for title_id in sub_database:
                e = sub_database[title_id]
                (title_name, title_id, region, size, type, serial, publisher, dec_key, enc_key, crypto_seed, common_key) = (e['title_name'], e['title_id'], e['region'], e['image_size'], e['type'], e['serial'], e['publisher'], e['dec_key'], e['enc_key'], e['crypto_seed'], e['common_key'])
                if not e['title_name']:  title_name  = ''.rjust(title_name_limit, '-')
                if not e['title_id']:    title_id    = ''.rjust(title_id_limit, '-')
                if not e['region']:      region      = ''.rjust(region_limit, '-')
                if not e['image_size']:  size        = ''.rjust(size_limit, '-')
                if not e['type']:        type        = ''.rjust(type_limit, '-')
                if not e['serial']:      serial      = ''.rjust(serial_limit, '-')
                if not e['publisher']:   publisher   = ''.rjust(publisher_limit, '-')
                if not e['dec_key']:     dec_key     = ''.rjust(dec_key_limit, '-')
                if not e['enc_key']:     enc_key     = ''.rjust(enc_key_limit, '-')
                if not e['crypto_seed']: crypto_seed = ''.rjust(crypto_seed_limit, '-')
                if not e['common_key']:  common_key  = ''.rjust(common_key_limit, '-')
                if type.upper() in tid_index: type = tid_index[type.upper()]
                try:
                    print(format_string.format(title_name, title_id, dec_key, enc_key, crypto_seed, region, size, type, serial, publisher, common_key))
                except UnicodeEncodeError:
                    print((format_string.format(title_name, title_id, dec_key, enc_key, crypto_seed, region, size, type, serial, publisher, common_key)).encode('utf-8'))
        if not args.verbose:
            self.log.print_err()


#====================#
# Frontend UI Logic  #
#====================#
class AppName(Tk):
## FIXIT FIX EVERYTHING
    def __init__(self, t_handler, root=None):
        self.log = t_handler.log
        Tk.__init__(self, root)
        self.title(AppText().program_title)
        icon_base64 ="""R0lGODlhIAAgAOfYAKYAAKcAAKgAAKUBAakAAKoAAKsAAKgBAawAAK0AAK4AAKwBAa0BAa4BAa0C\nAq4DA64EBK4FBa8ICKwMDLALC60MDLEQD7IRELETE7IUFLMUFLIWFrMWFrMYF7QYGLQZGbUZGbYb\nG7UcHLYeHbYfH7YhILciIrUlJbYlJbcnJrgoJ7krKrksK7otLbouLbsxMbsyMbo0NLk1NL05OL47\nOlZXV748O1dYV7o+PcBCQbtEQ71EQ75EQ79EQ8BEQ8BERMFGRcJKSWJkY8JKSmNkZL5MS8NNTMNO\nTcRPTsRQT8RRUMVUU8VVVMdaWchdXMVfXshfXsViYcZiYcdiYchiYcliYcZjYsdjYcdjYshjYslj\nYcljYspjYcpjYspkY8tpZ8tracxsa8xubc1ubcl2ds51c891c892ddB5d8+BgNCBgNGBgNKBgNKC\ngNaBgdSGhdSJh9SJiNOLitWLitSMi9WMitWMi9aMi9ONjdWNi9aNi9eNi9eOi9mOi9iQjtiUktiW\nlNmYltmamNmbmdqcmq6urNyjodimpbGxrtmnp9iop9mop9qop9uoqN2optqpqNqpqdupqNupqdyp\nqNypqduqqdyqqdyqqt2qqd6qqN2rqd6rqd6rqt+rqd+rqt6sqd6sqt+squCsqt+tqeCtqt2urLq6\nuOCwrru7ueCysNO3ttS4uOG1stO5udW5uNW5uda5uNa6uNa6ude6uNe6ucPAv9e7udi7ueK5ttm8\nueK6t9e9usXCwNq9uePCweXDwebGxObHxNnPzdrPzOnQzufS0erU0erW0+vZ1uza1+3f3O7i4O7j\n4O/k4e/n5PDn5PHr6PHt6vHu6/Lv7PLw7fLw7vLx7vPy7///////////////////////////////\n////////////////////////////////////////////////////////////////////////////\n/////////////////////////////////////////////////////yH5BAEKAP8ALAAAAAAgACAA\nAAj+AP8JHEiwoMGDBlH98sOHD508dujs2WOnDh07dvrokaMH4508evD4MjUQERoFCRIoICCAgIEE\nCGIiMFAAAcyZBmQiIECmkEBjCxpAYbNGTRo1bdi0abOmKdKlS5u2UfNkwIFiAi8hMHKtq9evzaqU\ncALtq9kiAioJZGSgi9mvyl6kTGDj2NuuUQhEWksgy91r1jZ1mJugRbC31qToXVsAy19kySzMlZBA\nBbO3UwgsEjipr7W7y541mTsiRIIgn79mfiSQUl9qfzNFIJzSgzSzUwQoEhipQBbYbw09MDH3iyNi\n094q3vwvEQEsyd8SQuAmpYrUd/Pu/ffJN3CzzCD+gEhp5i9eAKAEdkrg9u+SuWHMX5uCIP0/Twm2\n/E11YS4L7G9RkQAnAnGiQHtmVQMDbYOYpxiB/4iCAIJm/ZJBAgwk4MAP35mlhQGhCBRKfuaVgUAc\nW8nHRQIh/kMJAvr9BQgEznBQhXwfYiJQIwBYYV4gIlwDhBfyZbZdJAI49tcZK1wDRg7yKQZJa32Z\nB4UL18xBQTQOEmAJZ8+Zx8QM1+iCADBdSsJZkuYpkcQ10WhgiHlGCiRJAD7+hcQYXUEBh3lUGKCJ\nQKOw+dcRb3T1hxiAGkCKQKQIcIV5PwTSFStD0InAo/+UEoAMt701DQmCdIXLBwB6JU0MCJwi0DBs\nExRwAg898ODDrT3QgMAGO/CQAgI46NArD8T2gEIBFQgjEBGHYFBAAQQEIIABOSVgAEsFUEsAAAR0\nSwC0BWDAiBAD3cDLLr3kosoqrrxiyy2zzOKKK7fkAksssdAiyyuyyNJKLTUgJPDABwUEADs="""
        img = PhotoImage(data=icon_base64)
        self.call('wm', 'iconphoto', self._w, img)
        self.geometry('300x150')
        self.createWidgets()

    def createWidgets(self):
        self.quit_button = ttk.Button(self, text=u'Quit', command=self.quit)
        self.quit_button.pack()
        #self.color_picker = ttk.Button(self, text=color, command=self.btn_load_ticketdb)
        #self.color_picker.pack()
        messagebox.showerror(AppText().not_implemented_yet.split(':')[0], AppText().not_implemented_yet % 'GUI mode')
        self.quit()
        
    def btn_load_ticketdb(self):
        error, result = t_handler.load_bin('ticket.db')
        if error:
            messagebox.showerror(result.split(':')[0], result)
        else:
            messagebox.showinfo('Success', result)


#====================#
# Reimplementations  #
#====================#
def pmkdir(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

class logging_handler:
    def __init__(self):
        self.verbose = 0
        self.log = []
        self.add([0, 'Initializing log...'])
    def add(self, entry, err=0):
        self.log.append([err, entry])
        if self.verbose: print(entry)
        return
    def print_err(self):
        for entry in self.log:
            if entry[0] != 0:
                print(entry[1])
            


#====================#
#      Main Loop     #
#====================#
t_handler = title_database_handler()
start_time = time.clock()
cli = CliName(t_handler)
if cli.args:
    cli.parse_args()
if cli.args.gui_mode:
    app = AppName(t_handler)
    app.mainloop()
end_time = time.clock()
print('Total run time: %s' % str(end_time - start_time))   ##FIXIT