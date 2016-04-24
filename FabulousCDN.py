#!/usr/bin/env python3

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
# Imported Libraries
#----------------------------
import argparse, binascii, errno, io, os, queue, re, string, threading, urllib.request
import xml.etree.ElementTree as ET
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
# time     : Checking execution duration
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
# - convert everything to use bytearray
# Notes:
# - Requester_queue provides interface for pulling and writing to HDD
# - Writer_queue is exclusively called from worker_thread
# Credits:
# plailect, cearp
#----------------------------

#====================#
#   Generic Tools    #
#====================#
def pmkdir(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path): pass
        else: raise


class App:
    def __init__(self):
        ## Program Dialogue
        self.program_title        = u'[FabulousCDN]'
        self.force_gui_mode       = u'Forcing GUI mode, dropping all other arguments.'
        # Local dialogue
        self.invalid_title_id     = u'Invalid Title Id: %s'
        self.invalid_title_key    = u'Invalid Title Key: %s'
        self.invalid_crypto  = u'Invalid Crypto Seed: %s'
        self.invalid_console_id   = u'Invalid Common Key: %s'
        self.file_not_found       = u'File not found: %s doesn\'t exist.'
        self.no_database_found    = u'No entries in defined database.'
        self.incorrect_file_size  = u'Incorrect file size: %s'
        self.corrupted_ticket     = u'Corrupted ticket: %s doesn\'t match the ticket template.'
        self.imported_file        = u'%s entries found. %s imported.'
        self.exported_file        = u'%s entries written to %s.'
        self.failed_overwrite     = u'Failed to write: %s already exists.'
        # Web dialogue
        self.request_url_data     = u'Requesting data (%s): %d/%d attempts'
        self.request_url_suceed   = u'Retrieved data: %s'
        self.request_url_failed   = u'Failed to return data: %s'
        # -p --print title headers
        self.printing_database    = u'Printing current database...'
        self.print_default        = u'| %title_name | %title_id | %serial | %region | %size | %type | %publisher | %dec_key | %enc_key | %crypto | %console_id |'
        self.h_fmt_title_name     = u'Title Name'
        self.h_fmt_title_id       = u'Title ID'
        self.h_fmt_dec_key        = u'Decrypted Key'
        self.h_fmt_enc_key        = u'Encrypted Key'
        self.h_fmt_crypto    = u'Crypto Seed'
        self.h_fmt_region         = u'Region'
        self.h_fmt_size           = u'Size'
        self.h_fmt_type           = u'Type'
        self.h_fmt_serial         = u'Serial'
        self.h_fmt_publisher      = u'Publisher'
        self.h_fmt_console_id     = u'ConsoleID'
        # Thread dialogue
        self.added_to_queue       = u'Request %s added to queue.'
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

        ## Title ID index
        self.tid_index = {
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
        self.tid_index_extended = self.tid_index.copy()
        self.tid_index_extended.update({
            '00040000': self.eshop_title,
            '0004000E': self.eshop_update
            })

        ## Shared class variables
        self.verbose = 0
        self.logger = []
        self.title_database = {}
        
        ## Initialize all handlers
        self.w = web_handler(self)
        self.l = local_handler(self)
        self.t = thread_handler(self)
        self.lock = threading.Lock()


    def add_entry(self, title_id, database_index=None, title_name=None, publisher=None, region=None, language=None, release_group=None, image_size=None, serial=None, image_crc=None, file_name=None, release_name=None, trimmed_size=None, firmware=None, type=None, card=None, decrypted_title_key=None, encrypted_title_key=None, crypto_seed=None, console_id=None):
        entry_template = {
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
                'file_name'      : file_name,         #Useless metadata
                'release_name'   : release_name,      #Useless metadata
                'trimmed_size'   : trimmed_size,      #Useless metadata
                'firmware'       : firmware,          #Useless metadata
                'type'           : title_id[:][:8], ##Drop 3dsdb typing for tid_high typing
                'card'           : card,              #Useless metadata
                'dec_key'        : decrypted_title_key,
                'enc_key'        : encrypted_title_key,
                'crypto'         : crypto_seed,
                'console_id'     : console_id
                }
        # All caps certain entries
        capitalize = ['title_id', 'dec_key', 'enc_key', 'crypto', 'console_id', 'region', 'language', 'image_size', 'serial', 'image_crc', 'trimmed_size', 'type', 'card']
        # If missing data isn't passed to entry, use previous values.
        for info in entry_template:
            if not entry_template[info] and title_id in self.title_database: entry_template[info] = self.title_database[title_id][info]
            if entry_template[info] and info in capitalize: entry_template[info] = entry_template[info].upper()
        with self.lock:
            self.title_database.update({title_id: entry_template})

    def replace_string(self, format_string, limit_length=True):
        replacement_strings = [
            ['%title_name', 36],
            ['%title_id', 16],
            ['%dec_key', 32],
            ['%enc_key', 32],
            ['%crypto', 32],
            ['%console_id', 10],
            ['%region', 6],
            ['%size', 6],
            ['%type', 20],
            ['%serial', 10],
            ['%publisher', 20]
            ]
        for i, string in enumerate(replacement_strings):
            if limit_length:
                format_string = format_string.replace(string[0], '{{{0}: ^{1}.{1}}}'.format(i, string[1]))
            else:
                format_string = format_string.replace(string[0], '{{0}}'.format(i))
        return format_string

    #####-----     http://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console     -----#####
    def progress_bar(self, current_iteration, total_iterations, custom_string='[=>> ]', decimals=1, bar_length=50, prefix='Progress:', suffix=''):
        filled_length    = int(round(bar_length * current_iteration / float(total_iterations)))
        percents        = round(100.00 * (current_iteration / float(total_iterations)), decimals)
        bar             = (custom_string[1] * filled_length) + custom_string[(current_iteration % 2)+2] + (custom_string[4] * (bar_length - filled_length))
        sys.stdout.write('\r%s %s%s%s %s%s %s' % (prefix, custom_string[0], bar, custom_string[5], percents, '%', suffix)),
        sys.stdout.flush()
        if current_iteration == total_iterations:
            print("\n")
    def log(self, entry, err=0):
        self.logger.append([err, entry])
        if self.verbose: 
            self.xprint(entry)
    def print_err(self):
        for entry in self.logger:
            if entry[0] !=0:
                self.xprint(entry[1])
    def xprint(self, line):
        try:
            print(line)
        except UnicodeEncodeError:
            print(line.encode('utf-8'))


class web_handler:
    def __init__(self, App):
        self.app = App
        self.app.log('Web handler initialized.')
    '''def pull_title_metadata(self, title_id):
        self.log.add(self.app.not_implemented_yet % 'pull title metadata', err=-1)  ##FIXIT'''
    def request_url(self, url):
        n_of_attempts = 3
        for attempt in range(n_of_attempts):
            try:
                if(attempt < n_of_attempts):
                    self.app.log(self.app.request_url_data % (url, attempt+1, n_of_attempts))
                    url_data = urllib.request.urlopen(url)
            except Exception as e:
                self.app.log(e) ##FIXIT
                error = True
                continue
            error = False
            break
        if error: return self.app.log(self.app.request_url_failed % url, err=-1)
        bytes = io.BytesIO(url_data.read())
        self.app.log(self.app.request_url_suceed % url)
        return bytes

class local_handler:
    def __init__(self, App):
        self.app = App
        self.app.log('Local handler initialized.')
        self.ticket_template = '00010004d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC00000000000000000000000000AAAAAAAAAAAAAAAA00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        self.ticket_magic    = '00010004919ebe464ad0f552cd1b72e7884910cf55a9f02e50789641d896683dc005bd0aea87079d8ac284c675065f74c8bf37c88044409502a022980bb8ad48383f6d28a79de39626ccb2b22a0f19e41032f094b39ff0133146dec8f6c1a9d55cd28d9e1c47b3d11f4f5426c2c780135a2775d3ca679bc7e834f0e0fb58e68860a71330fc95791793c8fba935a7a6908f229dee2a0ca6b9b23b12d495a6fe19d0d72648216878605a66538dbf376899905d3445fc5c727a0e13e0e2c8971c9cfa6c60678875732a4e75523d2f562f12aabd1573bf06c94054aefa81a71417af9a4a066d0ffc5ad64bab28b1ff60661f4437d49e1e0d9412eb4bcacf4cfd6a3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137a0894ad505bb6c67e2e5bdd6a3bec43d910c772e9cc290da58588b77dcc11680bb3e29f4eabbb26e98c2601985c041bb14378e689181aad770568e928a2b98167ee3e10d072beef1fa22fa2aa3e13f11e1836a92a4281ef70aaf4e462998221c6fbb9bdd017e6ac590494e9cea9859ceb2d2a4c1766f2c33912c58f14a803e36fccdcccdc13fd7ae77c7a78d997e6acc35557e0d3e9eb64b43c92f4c50d67a602deb391b06661cd32880bd64912af1cbcb7162a06f02565d3b0ece4fcecddae8a4934db8ee67f3017986221155d131c6c3f09ab1945c206ac70c942b36f49a1183bcd78b6e4b47c6c5cac0f8d62f897c6953dd12f28b70c5b7df751819a9834652625000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010003704138efbbbda16a987dd901326d1c9459484c88a2861b91a312587ae70ef6237ec50e1032dc39dde89a96a8e859d76a98a6e7e36a0cfe352ca893058234ff833fcb3b03811e9f0dc0d9a52f8045b4b2f9411b67a51c44b5ef8ce77bd6d56ba75734a1856de6d4bed6d3a242c7c8791b3422375e5c779abf072f7695efa0f75bcb83789fc30e3fe4cc8392207840638949c7f688565f649b74d63d8d58ffadda571e9554426b1318fc468983d4c8a5628b06b6fc5d507c13e7a18ac1511eb6d62ea5448f83501447a9afb3ecc2903c9dd52f922ac9acdbef58c6021848d96e208732d3d1d9d9ea440d91621c7a99db8843c59c1f2e2c7d9b577d512c166d6f7e1aad4a774a37447e78fe2021e14a95d112a068ada019f463c7a55685aabb6888b9246483d18b9c806f474918331782344a4b8531334b26303263d9d2eb4f4bb99602b352f6ae4046c69a5e7e8e4a18ef9bc0a2ded61310417012fd824cc116cfb7c4c1f7ec7177a17446cbde96f3edd88fcd052f0b888a45fdaf2b631354f40d16e5fa9c2c4eda98e798d15e6046dc5363f3096b2c607a9d8dd55b1502a6ac7d3cc8d8c575998e7d796910c804c495235057e91ecd2637c9c1845151ac6b9a0490ae3ec6f47740a0db0ba36d075956cee7354ea3e9a4f2720b26550c7d394324bc0cb7e9317d8a8661f42191ff10b08256ce3fd25b745e5194906b4d61cb4c2e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007be8ef6cb279c9e2eee121c6eaf44ff639f88f078b4b77ed9f9560b0358281b50e55ab721115a177703c7a30fe3ae9ef1c60bc1d974676b23a68cc04b198525bc968f11de2db50e4d9e7f071e562dae2092233e9d363f61dd7c19ff3a4a91e8f6553d471dd7b84b9f1b8ce7335f0f5540563a1eab83963e09be901011f99546361287020e9cc0dab487f140d6626a1836d27111f2068de4772149151cf69c61ba60ef9d949a0f71f5499f2d39ad28c7005348293c431ffbd33f6bca60dc7195ea2bcc56d200baf6d06d09c41db8de9c720154ca4832b69c08c69cd3b073a0063602f462d338061a5ea6c915cd5623579c3eb64ce44ef586d14baaa8834019b3eebeed3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        # Read and write binary files. Write should never be called from any frontend
    def write_bin(self, type, database):
        if type == 'write_decrypted':
            pass
        if type == 'write_encrypted':
            pass
        if type == 'write_crypto':
            pass
        if type == 'write_ticket':
            pass
        if type == 'write_xml':
            pass
        if type == 'write_csv':
            pass
    def read_bin(self, type, data):
        # parses bytes into title database
        # This could be "simplified" into a more complex looking if statement with less repetitive code, but w/e #Clarity
        if not data: return
        n_entries = 0
        if type.split('_')[1] == 'decrypted':
            n_entries = len(data.read()) / 32
            data.seek(16, os.SEEK_SET)
            for i in range(int(n_entries)):
                c_id = binascii.hexlify(data.read(4)).decode('utf-8')
                data.seek(4, os.SEEK_CUR)
                title_id = binascii.hexlify(data.read(8)).decode('utf-8')
                key = binascii.hexlify(data.read(16)).decode('utf-8')
                self.app.add_entry(title_id, decrypted_title_key=key, console_id=c_id)
        if type.split('_')[1] == 'encrypted':
            n_entries = len(data.read()) / 32
            data.seek(16, os.SEEK_SET)
            for i in range(int(n_entries)):
                c_id = binascii.hexlify(data.read(4)).decode('utf-8')
                data.seek(4, os.SEEK_CUR)
                title_id = binascii.hexlify(data.read(8)).decode('utf-8')
                key = binascii.hexlify(data.read(16)).decode('utf-8')
                self.app.add_entry(title_id, encrypted_title_key=key, console_id=c_id)
        if type.split('_')[1] == 'crypto':
            n_entries = len(data.read()) / 32
            data.seek(16, os.SEEK_SET)
            for i in range(int(n_entries)):
                title_id = binascii.hexlify(data.read(8)).decode('utf-8')
                key = binascii.hexlify(data.read(16)).decode('utf-8')
                data.seek(8, os.SEEK_CUR)
                self.app.add_entry(title_id, crypto_seed=key)
        if type.split('_')[1] == 'ticket':
            ticket = data.read()
            ticket = bytearray(ticket)
            title_id = binascii.hexlify(ticket[0x1DC:0x1E4]).decode('utf-8')
            key = binascii.hexlify(ticket[0x1BF:0x1CF]).decode('utf-8')
            n_entries = 1
            self.app.add_entry(title_id, encrypted_title_key=key)
        if type.split('_')[1] == 'ticketdb':
            tickets = data.read()
            pattern = re.compile(b'Root-CA00000003-XS0000000c')
            ticket_offsets = [match.start() for match in re.finditer(b'Root-CA00000003-XS0000000c', tickets)]
            tickets = bytearray(tickets)
            for offset in ticket_offsets:
                enc_title_key    = tickets[offset+0x7F:offset+0x8F]
                title_id         = tickets[offset+0x9C:offset+0xA4]
                c_id = tickets[offset+0xB1]  # common_key_index is worthless for what this script wants to do, but extra checks are always nice
                # Check if potentially valid ticket, offset+0x7C is always 0x1.
                if tickets[offset+0x7C] != 0x1: continue
                if c_id > 5: continue
                # Add entry to database
                n_entries += 1
                title_id = binascii.hexlify(title_id).decode('utf-8')
                key = binascii.hexlify(enc_title_key).decode('utf-8')
                self.app.add_entry(title_id, encrypted_title_key=key, console_id=c_id)
        if type.split('_')[1] == 'xml':
            tree = ET.ElementTree(file=data)
            root = tree.getroot()
            n_entries = len(root)
            for i in range(n_entries):
                e=root[i]
                self.app.add_entry(
                    title_id = e[8].text,
                    database_index = e[0].text,
                    title_name = e[1].text,
                    publisher = e[2].text,
                    region = e[3].text,
                    language = e[4].text,
                    release_group = e[5].text,
                    image_size = e[6].text,
                    serial = e[7].text,
                    image_crc = e[9].text,
                    file_name = e[10].text,
                    release_name = e[11].text,
                    trimmed_size = e[12].text,
                    firmware = e[13].text,
                    type = e[14].text,
                    card = e[15].text
                    )
        if type.split('_')[1] == 'csv':
            data.readline() # Title header
            csv_file = data.read().decode('utf-8')
            pattern = re.compile(r'(?P<title_name>[^"]+)(?:,"="")(?P<title_ID>[^,]+)(?:""",)(?P<enc_key>[^,]+)(?:,)(?P<region>[^,]+)(?:,")(?P<serial>[^"]+)(?:",")(?P<publisher>[^"]+)(?:",)(?P<ver_num>[^,]+)(?:,)(?P<size>[0-9]+.[0-9]+)')
            n_entries = len(re.findall(pattern, csv_file))
            for (title_name, title_id, enc_key, region, serial, publisher, ver_num, size) in re.findall(pattern,csv_file):
                self.app.add_entry(title_id, title_name=title_name[2:], encrypted_title_key=enc_key, region=region, serial=serial, publisher=publisher, image_size=size)
        return n_entries
    def load_file(self, type, path):
        # loads file into memory and passes back bytes
        if not os.path.isfile(path):
            return self.app.log(self.app.file_not_found % path, err=-1)
        if type in ['load_decrypted', 'load_encrypted', 'load_crypto']: size_check = (os.path.getsize(path) % 32) - 16
        elif type == 'load_ticket': size_check = (os.path.getsize(path) % 2640)
        elif type == 'load_ticketdb': size_check = (os.path.getsize(path) % 37221888)
        elif type == 'load_xml': 
            if os.path.getsize(path) > 392: size_check = 0
            else: size_check = 1
        elif type == 'load_csv':
            if os.path.getsize(path) > 96: size_check = 0
            else: size_check = 1
        if size_check != 0: return self.app.log(self.app.incorrect_file_size % path, err=-1)
        bytes = open(path, 'rb')
        return bytes

class thread_handler:
    def __init__(self, App):
        self.app = App
        self.app.log('Thread handler initialized.')
        self.request_queue = queue.Queue()
        self.write_queue = queue.Queue()
        self.main_thread = threading.currentThread()
        self.queue_data = []
    def worker_thread(self):
        # Parses user requests and passes requests to the writer_queue
        a, queue_data = self.request_queue.get()
        type, data = (a['type'][:], a['data'])
        if type == 'pull_decrypted': 
            data = self.app.w.request_url('http://3ds.nfshost.com/download')
        if type == 'pull_encrypted': 
            data = self.app.w.request_url('http://3ds.nfshost.com/downloadenc')
        if type == 'pull_xml': 
            data = self.app.w.request_url('http://3dsdb.com/xml.php')
        if type == 'pull_metadata': data = 0
        if type in ['pull_decrypted', 'pull_encrypted', 'pull_xml']:
            type = 'load_%s' % type.split('_')[1]
        # pass on a[type] and data, if a[type] pull_, then read_bin. if a[type] load_, then load_file
        if type == 'load_decrypted':
            if a['type'] == 'load_decrypted': data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_encrypted':
            if a['type'] == 'load_encrypted': data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_crypto':
            data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_ticket': 
            data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_ticketdb': 
            data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_xml': 
            if a['type'] == 'load_xml': data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if type == 'load_csv': 
            data = self.app.l.load_file(a['type'], a['file_in'])
            data = self.app.l.read_bin(a['type'], data)
        if a['type'] in ['pull_decrypted', 'pull_encrypted', 'pull_xml']:
            if not a['temporary']: type = 'write_%s' % type.split('_')[1]
        # pass on type and data, if a[type] pull_ and a[temporary] not set, write to default
        if type in ['pull_tmd', 'write_ticket']: data = self.app.w.request_url('http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/%s/tmd' % a['title_id'])
        if type == 'write_decrypted': data = 0
        if type == 'write_encrypted': data = 0
        if type == 'write_crypto': data = 0
        if type == 'write_ticket': data = 0
        if type == 'write_xml': data = 0
        if type == 'write_csv': data = 0
        a.update({'data': data})
        queue_data.append(a)
        self.request_queue.task_done()
        return
    def writer_thread(self):
        # Writes all incoming data to file
        a, queue_data = self.write_queue.get()
        output = ''
        if a['output_dir']: output += '%s/' % a['output_dir']
        if a['file_out']: output += '%s' % a['file_out']
        type = a['type']
        if type == 'write_decrypted': output += 'decTitleKeys.bin'
        elif type == 'write_encrypted': output += 'encTitleKeys.bin'
        elif type == 'write_crypto': output += 'seeddb.bin'
        elif type == 'write_ticket': output += '%s.tik' % a['title_id']
        elif type == 'write_xml': output += '3dsreleases.xml'
        elif type == 'write_csv': output += 'titles.csv'
        # User-defined string
        if a['title_id']:
            b = self.app.title_database[a['title_id']].copy()
            for key in b:
                if not b[key]: b[key] = 'unk'
            format_string = self.app.replace_string(output, limit_length=False)
            format_string.format(b['title_name'], b['title_id'], b['dec_key'], b['enc_key'], b['crypto'], b['console_id'], b['region'], b['size'], b['type'], b['serial'], b['publisher'])
        if not a['overwrite'] and os.path.isfile(output): return self.app.log(self.app.failed_overwrite % output, err=-1) ## FIXIT
        #pmkdir(output.rsplit(os.sep, 1))    ##Commented out write to file temporarily (for testing purposes)
        #with open(output, 'wb') as file_handler:
        #    file_handler.write(a['data'])
        #    file_handler.close()
        self.app.log('Write request completed: %s' % output) ##FIXIT
        self.write_queue.task_done()
        return
    def requester_queue(self, title_id=None, key=None, type=None, file_in=None, output_dir=None, file_out=None, data=None, overwrite=False, tmp=False):
        # Adds a new user request to the queue
        args = {
            'title_id': title_id,
            'key': key,
            'type': type,
            'file_in': file_in,
            'output_dir': output_dir,
            'file_out': file_out,
            'data': data,
            'overwrite': overwrite,
            'temporary': tmp
            }
        self.request_queue.put((args, self.queue_data))
        thread_handle = threading.Thread(target=self.worker_thread)
        thread_handle.start()
        self.app.log(self.app.added_to_queue % type)  ##FIXIT
    def writer_queue(self, title_id=None, key=None, type=None, file_in=None, output_dir=None, file_out=None, data=None, overwrite=False, tmp=False):
        # Adds a new write request to the queue
        args = {
            'title_id': title_id,
            'key': key,
            'type': type,
            'file_in': file_in,
            'output_dir': output_dir,
            'file_out': file_out,
            'data': data,
            'overwrite': overwrite,
            'temporary': tmp
            }
        # If the writer thread is active, wait for it to rejoin main thread
        for thread in threading.enumerate():
            if thread is self.writer_thread:
                thread.join()
        # Spawn new writer thread
        self.write_queue.put((args, self.queue_data))
        self.writer_handle = threading.Thread(target=self.writer_thread, name='Thread-Writer')
        self.writer_handle.start()
        self.app.log(self.app.added_to_queue % type)  ##FIXIT
    def join_threads(self):
        # Wait for queue to finish before continuing
        for thread in threading.enumerate():
            if thread is self.main_thread:
                continue
            thread.join()


class CliFrontend:
    def __init__(self, App):
        self.app = App
        self.app.log('Cli frontend initialized.')
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
        parser.add_argument('-cs',  '--crypto',                     action='store',       dest='crypto',                              help='Add a crypto seed for the Title ID')
        parser.add_argument('-ck',  '--console_id',                 action='store',       dest='console_id',                               help='Add a common key for the Title ID')
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
        parser.add_argument('-fi',  '--filter',                     action='store',       dest='filter',                                   help='Filters output. Available input: USA, JPN, TWN, HKG, KOR, EUR, decrypted, encrypted, crypto, title, dlc, update, app, dlplay, demo, sysapp, sysapplet, sysmod, sysfirm, sysarc, twlsys, twlarc, <title_id>, <title_name>, <image_size>')
        parser.add_argument('-f',   '--force',                      action='store_true',  dest='overwrite',                                help='Force overwrite files')
        parser.add_argument('-o',   '--out_dir',         nargs='?', action='store',       dest='output_dir',      const='output',          help='Custom output directory to store output')
        parser.add_argument('-nh',  '--no_hash',                    action='store_true',  dest='no_hash',                                  help='Skip hash check')
        parser.add_argument('-nd',  '--no_download',                action='store_true',  dest='no_download',                              help='Don\'t download title')
        parser.add_argument('-nb',  '--no_build',                   action='store_true',  dest='no_build',                                 help='Don\'t build .3ds or .cia file')
        parser.add_argument('-n3',  '--no_3ds',                     action='store_true',  dest='no_3ds',                                   help='Don\'t build .3ds file')
        parser.add_argument('-nc',  '--no_cia',                     action='store_true',  dest='no_cia',                                   help='Don\'t build .cia file')
        self.args = parser.parse_args()
    def parse_arguments(self):
        args = self.args
        # Convert necessary args to .upper() before doing anything
        if args.title_id: args.title_id = args.title_id.upper()
        if args.dec_title_key: args.dec_title_key = args.dec_title_key.upper()
        if args.enc_title_key: args.enc_title_key = args.enc_title_key.upper()
        if args.crypto: args.crypto = args.crypto.upper()
        if args.console_id: args.console_id = args.console_id.upper()
        # Parse arguments (maybe add loading priority, ex. load xml after csv)
        if args.verbose:
            self.app.verbose = 1
        if args.decTitleKey_in: self.app.t.requester_queue(type='load_decrypted', file_in=args.decTitleKey_in)
        if args.encTitleKey_in: self.app.t.requester_queue(type='load_encrypted', file_in=args.encTitleKey_in)
        if args.seeddb_in: self.app.t.requester_queue(type='load_crypto', file_in=args.seeddb_in)
        if args.xml_in: self.app.t.requester_queue(type='load_xml', file_in=args.xml_in)
        if args.pull_data:
            if args.pull_data == 'local':
                self.app.t.requester_queue(type='load_csv', file_in='data/titles.csv')
                self.app.t.requester_queue(type='load_xml', file_in='data/3dsreleases.xml')
                self.app.t.requester_queue(type='load_decrypted', file_in='data/decTitleKeys.bin')
                self.app.t.requester_queue(type='load_encrypted', file_in='data/encTitleKeys.bin')
                self.app.t.requester_queue(type='load_crypto', file_in='data/seeddb.bin')
                self.app.t.requester_queue(type='load_ticketdb', file_in='data/ticket.db')
            elif args.pull_data in ['web', 'tmp']:
                if args.pull_data == 'tmp': temp = True
                else: temp = False
                self.app.t.requester_queue(type='pull_xml', tmp=temp)
                self.app.t.requester_queue(type='pull_decrypted', tmp=temp)
                self.app.t.requester_queue(type='pull_encrypted', tmp=temp)
        
        if args.ticket_in: self.app.t.requester_queue(type='load_ticket', file_in=args.ticket_in)
        
        
        self.app.t.join_threads()
        sub_database = self.app.title_database.copy()
        if args.print_format:
            self.print_database(sub_database, print_format=args.print_format, title_header=args.title_header)


    def print_database(self, database, print_format='default', title_header=False):
        if print_format != 'default':
            format_string = print_format
        else:
            format_string = self.app.print_default
        format_string = self.app.replace_string(format_string)
        if title_header:
            head_line = format_string.format(
                self.app.h_fmt_title_name,
                self.app.h_fmt_title_id,
                self.app.h_fmt_dec_key,
                self.app.h_fmt_enc_key,
                self.app.h_fmt_crypto,
                self.app.h_fmt_console_id,
                self.app.h_fmt_region,
                self.app.h_fmt_size,
                self.app.h_fmt_type,
                self.app.h_fmt_serial,
                self.app.h_fmt_publisher
                )
            split_line = re.sub(r'[^\{0-9:<^>.\}]', '-', format_string)
            split_line = re.sub(r'[0-9]+:', '0:', split_line)
            split_line = split_line.format('')
            split_line = '{1}{0}{1}'.format(split_line[1:-1], '|')
            self.app.log(self.app.printing_database)
            self.app.xprint('{0}\n{1}\n{0}'.format(split_line, head_line))
            tid_index = self.app.tid_index_extended
            for title_id in database:
                e = database[title_id]
                (title_name, title_id, region, size, type, serial, publisher, dec_key, enc_key, crypto, console_id) = (e['title_name'], e['title_id'], e['region'], e['image_size'], e['type'], e['serial'], e['publisher'], e['dec_key'], e['enc_key'], e['crypto'], e['console_id'])
                if not e['title_name']:  title_name  = ''.rjust(20, '-')
                if not e['title_id']:    title_id    = ''.rjust(8, '-')
                if not e['region']:      region      = ''.rjust(3, '-')
                if not e['image_size']:  size        = ''.rjust(5, '-')
                if not e['type']:        type        = ''.rjust(6, '-')
                if not e['serial']:      serial      = ''.rjust(10, '-')
                if not e['publisher']:   publisher   = ''.rjust(8, '-')
                if not e['dec_key']:     dec_key     = ''.rjust(16, '-')
                if not e['enc_key']:     enc_key     = ''.rjust(16, '-')
                if not e['crypto']: crypto = ''.rjust(16, '-')
                if not e['console_id']:  console_id  = ''.rjust(4, '-')
                if type in tid_index: type = tid_index[type]
                self.app.xprint(format_string.format(title_name, title_id, dec_key, enc_key, crypto, console_id, region, size, type, serial, publisher))


from tkinter import *
from tkinter import font
from tkinter.ttk import *
class GuiFrontend(Tk):
    def __init__(self, App, root=None):
        self.app = App
        self.app.log('Gui frontend initialized.')
        Tk.__init__(self, root)
        self.title(self.app.program_title)
        icon_base64 ="""R0lGODlhIAAgAOfYAKYAAKcAAKgAAKUBAakAAKoAAKsAAKgBAawAAK0AAK4AAKwBAa0BAa4BAa0C\nAq4DA64EBK4FBa8ICKwMDLALC60MDLEQD7IRELETE7IUFLMUFLIWFrMWFrMYF7QYGLQZGbUZGbYb\nG7UcHLYeHbYfH7YhILciIrUlJbYlJbcnJrgoJ7krKrksK7otLbouLbsxMbsyMbo0NLk1NL05OL47\nOlZXV748O1dYV7o+PcBCQbtEQ71EQ75EQ79EQ8BEQ8BERMFGRcJKSWJkY8JKSmNkZL5MS8NNTMNO\nTcRPTsRQT8RRUMVUU8VVVMdaWchdXMVfXshfXsViYcZiYcdiYchiYcliYcZjYsdjYcdjYshjYslj\nYcljYspjYcpjYspkY8tpZ8tracxsa8xubc1ubcl2ds51c891c892ddB5d8+BgNCBgNGBgNKBgNKC\ngNaBgdSGhdSJh9SJiNOLitWLitSMi9WMitWMi9aMi9ONjdWNi9aNi9eNi9eOi9mOi9iQjtiUktiW\nlNmYltmamNmbmdqcmq6urNyjodimpbGxrtmnp9iop9mop9qop9uoqN2optqpqNqpqdupqNupqdyp\nqNypqduqqdyqqdyqqt2qqd6qqN2rqd6rqd6rqt+rqd+rqt6sqd6sqt+squCsqt+tqeCtqt2urLq6\nuOCwrru7ueCysNO3ttS4uOG1stO5udW5uNW5uda5uNa6uNa6ude6uNe6ucPAv9e7udi7ueK5ttm8\nueK6t9e9usXCwNq9uePCweXDwebGxObHxNnPzdrPzOnQzufS0erU0erW0+vZ1uza1+3f3O7i4O7j\n4O/k4e/n5PDn5PHr6PHt6vHu6/Lv7PLw7fLw7vLx7vPy7///////////////////////////////\n////////////////////////////////////////////////////////////////////////////\n/////////////////////////////////////////////////////yH5BAEKAP8ALAAAAAAgACAA\nAAj+AP8JHEiwoMGDBlH98sOHD508dujs2WOnDh07dvrokaMH4508evD4MjUQERoFCRIoICCAgIEE\nCGIiMFAAAcyZBmQiIECmkEBjCxpAYbNGTRo1bdi0abOmKdKlS5u2UfNkwIFiAi8hMHKtq9evzaqU\ncALtq9kiAioJZGSgi9mvyl6kTGDj2NuuUQhEWksgy91r1jZ1mJugRbC31qToXVsAy19kySzMlZBA\nBbO3UwgsEjipr7W7y541mTsiRIIgn79mfiSQUl9qfzNFIJzSgzSzUwQoEhipQBbYbw09MDH3iyNi\n094q3vwvEQEsyd8SQuAmpYrUd/Pu/ffJN3CzzCD+gEhp5i9eAKAEdkrg9u+SuWHMX5uCIP0/Twm2\n/E11YS4L7G9RkQAnAnGiQHtmVQMDbYOYpxiB/4iCAIJm/ZJBAgwk4MAP35mlhQGhCBRKfuaVgUAc\nW8nHRQIh/kMJAvr9BQgEznBQhXwfYiJQIwBYYV4gIlwDhBfyZbZdJAI49tcZK1wDRg7yKQZJa32Z\nB4UL18xBQTQOEmAJZ8+Zx8QM1+iCADBdSsJZkuYpkcQ10WhgiHlGCiRJAD7+hcQYXUEBh3lUGKCJ\nQKOw+dcRb3T1hxiAGkCKQKQIcIV5PwTSFStD0InAo/+UEoAMt701DQmCdIXLBwB6JU0MCJwi0DBs\nExRwAg898ODDrT3QgMAGO/CQAgI46NArD8T2gEIBFQgjEBGHYFBAAQQEIIABOSVgAEsFUEsAAAR0\nSwC0BWDAiBAD3cDLLr3kosoqrrxiyy2zzOKKK7fkAksssdAiyyuyyNJKLTUgJPDABwUEADs="""
        img = PhotoImage(data=icon_base64)
        self.call('wm', 'iconphoto', self._w, img)
        self.init_ui()
    
    def init_ui(self):
        self.frame = Frame(self)
        self.notebook = Notebook(self.frame)
        
        frame_title_database = Frame(self.notebook, width=500, height=400)
        frame_credits_page = Frame(self.notebook, width=500, height=400)
        self.notebook.add(frame_title_database, text='Title Database')
        self.notebook.add(frame_credits_page, text='Credits')
        
        self.ctree = self.column_treeview(frame_title_database)
        
        self.frame.grid(row=0, column=0, sticky=(N,S,E,W))
        self.notebook.grid(row=0, column=0, sticky=(N,S,E,W))
        
        
        self.menu = Menu(self, tearoff=0)
        self.menu.add_command(label='Check decrypted title key', command=self.hello)
        self.menu.add_command(label='Save decrypted title key', command=self.hello)
        self.menu.add_command(label='Save encrypted title key', command=self.hello)
        self.menu.add_command(label='Save crypto seed', command=self.hello)
        def context_menu(event):
            try:
                self.tree_entry_selection = self.ctree.selection()
                self.menu.post(event.x_root, event.y_root)
            except Exception as e:
                print(e)
        self.ctree.bind("<Button-3>", context_menu)
        
        
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.frame.columnconfigure(0, weight=2)
        self.frame.rowconfigure(0, weight=2)
        
    def hello(self):
        for item in self.tree_entry_selection:
            entry = self.ctree.set(item)
            print(entry['Title ID'])
    def column_treeview(self, parent):
        columns = ('Title Name', 'Region', 'Size', 'Serial', 'Type', 'Publisher', 'Title ID', 'Console ID')
        self.ctree = Treeview(parent, columns=columns, show="headings")
        self.ctree.column('Title Name', width=150)
        self.ctree.column('Region', width=50)
        self.ctree.column('Size', width=40)
        self.ctree.column('Serial', width=75)
        self.ctree.column('Type', width=90)
        self.ctree.column('Publisher', width=90)
        self.ctree.column('Title ID', width=105)
        self.ctree.column('Console ID', width=70)
        for col in columns:
            self.ctree.heading(col, text=col)
        self.rebuild_treeview(self.ctree)
        self.ctree.pack(fill=BOTH, expand=1)
        self.search_frame = Frame(parent)
        self.search_frame.pack(fill=X)
        self.search_bar = Entry(self.search_frame)
        self.search_bar.pack(fill=BOTH, expand=1)
        #self.search_bar.grid(row=1, column=0)
        #self.search_bar.columnconfigure(0, weight=1)
        return self.ctree
    def rebuild_treeview(self, treeview):
        treeview.delete(*treeview.get_children())
        for title_id in self.app.title_database:
            e = self.app.title_database[title_id]
            treeview.insert('','end', values=[e['title_name'], e['region'], e['image_size'], e['serial'], e['type'], e['publisher'], e['title_id']])

#====================#
#      Main Loop     #
#====================#
import time
start_time = time.clock()
app = App()
cli = CliFrontend(app)
if cli.args:
    cli.parse_arguments()
if cli.args.gui_mode:
    gui = GuiFrontend(app)
    gui.mainloop()
end_time = time.clock()
if not app.verbose: app.print_err()
app.log('Total run time: %s' % str(end_time - start_time))   ##FIXIT