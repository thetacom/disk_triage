import sys
import os
import binascii
import xml
import json
from collections import OrderedDict
from colorama import Fore, Back, Style
import output_formats as formats
from ..common import *

class Image:
    current_location = 0

    def __init__(self, img_file):
        # Initialize main variables and objects
        self.file = img_file
        self.name = os.path.basename(self.file.name)
        self.physical_size = os.path.getsize(self.file.name)
        self.header = Image.Header(self)

        # Map key header attributes to image object
        self.cluster_size = 4096 # self.header.attr['cluster_size']
    
    def parse_address(self, address):
        partial_cluster_offset = address % self.cluster_size
        return {'partial_cluster_offset': partial_cluster_offset}

    def get_address_metadata(self, address):
        metadata = {}
        address_parts = self.parse_address(address)
        metadata['address'] = address
        metadata['address_parts'] = address_parts
        metadata['physical_offset'] = int(
            cluster_offset + (address % self.cluster_size))
        return metadata

    def read_physical_bytes(self, offset=0, qty=1):
        if offset + qty <= self.physical_size:
            self.file.seek(offset)
            data_read = self.file.read(qty)
        else:
            print("Invalid physical offset - Exceeds image file size. Offset:",
                  offset, "qty:", qty)
            data_read = b''
        return data_read

    def read_physical_cluster(self, offset):

        if offset < self.physical_size:
            if offset + self.cluster_size < self.physical_size:
                self.file.seek(offset)
                data_read = self.file.read(self.cluster_size)
            else:
                self.file.seek(offset)
                bytes_to_read = self.physical_size - offset
                data_read = self.file.read(bytes_to_read)
        else:
            print("Invalid physical offset - Cluster read exceeds image file size. Offset:",
                  offset, "qty:", self.cluster_size)
            data_read = b''
        return data_read


    def read_range(self, address, f_args):
        return {'metadata': {'address': address, 'address_parts': 'N/A', 
                            'l1': 'N/A', 'l2': 'N/A', 'physical_offset': address}, 
                'data': self.read_physical_bytes(address, f_args['increment'])}
    
    def read_data(self, f_args):
        data = self.iterate_addresses(
            self.read_range, f_args)
        return data


    def check(self, check_type, f_args={}):
        results = -1
        if check_type == 'consistency':
            print('Not Yet Implemented')
            # results = self.iterate_addresses(self.check_consistency, f_args)
        return results

    def check_consistency(self, address, fargs):
        address_metadata = self.get_address_metadata(address)
        consistency = []
        return {
            'address': address,
            'address_metadata': address_metadata,
            'consistency': consistency}

    def check_references(self):
        pass

    def iterate_addresses(self, function, f_args):
        results = []

        if 'increment' not in f_args:
            f_args['increment'] = self.cluster_size

        if 'start' not in f_args:
            f_args['start']=0
        
        if 'stop' not in f_args:
            f_args['stop'] = self.physical_size

        for address in range(
                f_args['start'],
                f_args['stop'],
                f_args['increment']):
            results.append(function(address, f_args))
        return results

    def comment(self, attr, value):
        if attr in Image.Header.structure:
            return self.header.comment(attr, value)
        else:
            return Fore.RED + "INVALID" + Style.RESET_ALL

    class Header:
        # 'header attribute name': [attr_offset, attr_size, 'description', 'type']
        structure = {}
        raw = b''
        attr = OrderedDict()
        def __init__(self, img):
            self.img = img

        def __str__(self):
            return repr(self)

        def __repr__(self):
            return self.img.file.name


    def plain_info(self, args):
        formats.plain_helpers.title('INFO')
        table_data = []
        table_data.append(['Filename', Fore.BLUE + self.name])
        table_data.append(['Physical Size', Fore.MAGENTA +
                           str(self.physical_size) + " bytes"])
        table_data.append(['Cluster Size', Fore.MAGENTA +
                           str(self.cluster_size) + " bytes"])
        if args.detailed:
            pass
        formats.plain_helpers.table(table_data,[25,45])

    def json_info(self, args):
        info = OrderedDict()
        info['filename'] = self.name
        info['physical_size'] = self.physical_size
        info['cluster_size'] = self.cluster_size
        if args.detailed:
            pass
        output = OrderedDict()
        output['info'] = info
        return json.dumps(output, indent=2)

    def plain_header(self, args):
        print("Format has no header.")

    def json_header(self, args):
        output = OrderedDict()
        output['header'] = 'No header'
        return json.dumps(output, indent = 2)

    def plain_data(self, args):
        f_args = {}
        # Parse provided address
        if args.address:
            try:
                if '0x' in args.address:
                    f_args['start'] = int(args.address[2:], 16)
                else:
                    f_args['start'] = int(args.address, 16)
            except:
                print("Invalid address")
                exit()
        else:
            f_args['start'] = 0
        
        #Set data read imcrement size
        if args.bytes:
            f_args['increment'] = 1
        elif args.sectors:
            f_args['increment'] = 512
        else:
            f_args['increment'] = self.cluster_size
        
        
        if args.all:
            f_args['stop'] = self.physical_size
        else:
            f_args['stop'] = int(f_args['start'] +
                                    args.number_of_chunks * f_args['increment'])
        if not args.no_metadata:
            #print(args)
            formats.plain_helpers.title('DATA')

        # Retrieve data chunks
        data = self.read_data(f_args)

        raw_data = b''
        previous_zeros = False
        for chunk in data:
            if args.raw:
                raw_data += chunk['data']
            else:
                if not args.no_metadata:
                    formats.plain_helpers.title(
                        'Phys Addr:' +
                        format(chunk['metadata']['address'], '#016x') +
                        ' / File Offset:' + format(chunk['metadata']['physical_offset'], '#016x'))
                if not args.no_data:
                    if all(v == 0 for v in chunk['data']):
                        formats.plain_helpers.title('Empty (' + str(len(chunk['data'])) + ' Bytes)', filler='*', color=Fore.LIGHTRED_EX)
                        previous_zeros = True
                    else:
                        formats.plain_helpers.data_table(
                            chunk['metadata']['address'], chunk['data'])
                        previous_zeros = False
                        #print(Fore.MAGENTA + str(chunk['data']), end='')
        print(Style.RESET_ALL)
        if args.raw:
            print(raw_data)


    def get_info(self, args):
        if args.format == 'plain':
            self.plain_info(args)
            self.plain_header(args)
            if args.all:
                pass
        elif args.format == 'json':
            output = OrderedDict()
            output.update(json.JSONDecoder(
                object_pairs_hook=OrderedDict).decode(self.json_info(args)))
            output.update(json.JSONDecoder(
                object_pairs_hook=OrderedDict).decode(self.json_header(args)))
            if args.all:
                pass
            print(json.dumps(output, indent=2))
        #elif args.format == 'xml':
        #    self.xml_info(args)
        #    self.xml_header(args)
        #    if args.all:
        #       pass

    def get_snapshots(self, args):
            formats.plain_helpers.title(
                'Format does not support snapshots', filler='*', color=Fore.LIGHTRED_EX)

    def get_map(self, args):
        if args.format == 'plain':
            print("Not Yet Implemented")

    def get_header(self, args):
        formats.plain_helpers.title(
            'Format has no header', filler='*', color=Fore.LIGHTRED_EX)

    def get_tables(self, args):
        formats.plain_helpers.title(
            'Format has no tables', filler='*', color=Fore.LIGHTRED_EX)

    def get_data(self, args, f_args={}):
        self.plain_data(args)


    def get_check(self, args, f_args={}):
        self.plain_info(args)
        self.plain_header(args)
        formats.plain_helpers.title(
            'No Checks Implemented', filler='*', color=Fore.LIGHTRED_EX)

    def mount(self, args):
        print("Not Yet Implemented")

    def unmount(self, args):
        print("Not Yet Implemented")
