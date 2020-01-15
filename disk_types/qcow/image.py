import binascii
import json
import math
import os
import sys
import xml
import zlib
from collections import OrderedDict

from colorama import Back, Fore, Style

import output_formats as formats

from ..common import *


class Image:
    # QCOW_MAGIC = ((ord('Q') << 24) | (ord('F') << 16) | (ord('I') << 8) | 0xfb)
    QCOW_MAGIC = 1363560955

    QCOW_CRYPT_NONE = 0
    QCOW_CRYPT_AES = 1
    QCOW_CRYPT_LUKS = 2

    QCOW_MAX_CRYPT_CLUSTERS = 32
    QCOW_MAX_SNAPSHOTS = 65536

    # Field widths in qcow2 mean normal cluster offsets cannot reach * 64PB
    # depending on cluster size, compressed clusters can have a
    # smaller limit(64PB for up to 16k clusters, then ramps down to
    # 512TB for 2M clusters).

    # QCOW_MAX_CLUSTER_OFFSET = (1 << 56) - 1
    QCOW_MAX_CLUSTER_OFFSET = 72057594037927935

    # 8 MB refcount table is enough for 2 PB images at 64k cluster size
    # (128 GB for 512 byte clusters, 2 EB for 2 MB clusters)
    # MiB = 1048576

    #QCOW_MAX_REFTABLE_SIZE = 8 * MiB
    QCOW_MAX_REFTABLE_SIZE = 8388608

    # 32 MB L1 table is enough for 2 PB images at 64k cluster size
    # (128 GB for 512 byte clusters, 2 EB for 2 MB clusters)
    # MiB = 1048576

    #QCOW_MAX_L1_SIZE = 32 * MiB
    QCOW_MAX_L1_SIZE = 33554432

    # Allow for an average of 1k per snapshot table entry, should be plenty of
    # space for snapshot names and IDs * /

    # QCOW_MAX_SNAPSHOTS_SIZE = 1024 * QCOW_MAX_SNAPSHOTS
    QCOW_MAX_SNAPSHOTS_SIZE = 67108864

    # Bitmap header extension constraints
    QCOW2_MAX_BITMAPS = 65535

    # QCOW2_MAX_BITMAP_DIRECTORY_SIZE = 1024 * QCOW2_MAX_BITMAPS
    QCOW2_MAX_BITMAP_DIRECTORY_SIZE = 67107840

    # L1 offset mask indicates the l2 offset portion of an l1 table entry
    # Bit Mask
    # 0000000011111111111111111111111111111111111111111111111111111111
    QCOW_L2_OFFSET_MASK = 72057594037927935

    # indicates the cluster descriptor portion of an l2 table entry
    # Bit Mask
    # 0011111111111111111111111111111111111111111111111111111111111111
    QCOW_DESCRIPTOR_MASK = 4611686018427387903

    # indicate that the refcount of the referenced cluster is exactly one.
    # Bit Mask
    # 1000000000000000000000000000000000000000000000000000000000000000
    QCOW_OFLAG_COPIED = 1 << 63

    # indicate that the cluster is compressed(they never have the copied flag)
    # Bit Mask
    # 0100000000000000000000000000000000000000000000000000000000000000
    QCOW_OFLAG_COMPRESSED = 1 << 62

    # The cluster reads as all zeros
    # 1-bit
    # Bit Mask 1
    QCOW_OFLAG_ZERO = 1 << 0

    # 9-bits
    # Bit Mask
    # 00000000000000000000000000000000000000000000000000000111111110
    QCOW_DESCRIPTOR_RESERVED_LOWER_MASK = 510

    # 6-bits
    # Bit Mask
    # 11111100000000000000000000000000000000000000000000000000000000
    QCOW_DESCRIPTOR_RESERVED_UPPER_MASK = 4539628424389459968

    # 47-bits
    # Bit Mask
    # 00000011111111111111111111111111111111111111111111111000000000
    QCOW_DESCRIPTOR_USEABLE_OFFSET_MASK = 72057594037927424

    MIN_CLUSTER_BITS = 9
    MAX_CLUSTER_BITS = 21

    # Defined in the qcow2 spec(compressed cluster descriptor)
    QCOW2_COMPRESSED_SECTOR_SIZE = 512
    QCOW2_COMPRESSED_SECTOR_MASK = ~(QCOW2_COMPRESSED_SECTOR_SIZE - 1)

    # Must be at least 2 to cover COW
    MIN_L2_CACHE_SIZE = 2  # cache entries

    # Must be at least 4 to cover all cases of refcount table growth
    MIN_REFCOUNT_CACHE_SIZE = 4  # clusters

    if sys.platform == "linux" or sys.platform == "linux2":
        # linux
        DEFAULT_L2_CACHE_MAX_SIZE = 32 * 1048576  # (32 * MiB)
        DEFAULT_CACHE_CLEAN_INTERVAL = 600  # seconds
    else:
        DEFAULT_L2_CACHE_MAX_SIZE = 8 * 1048576  # (8 * MiB)
        # Cache clean interval is currently available only on Linux, so must be 0
        DEFAULT_CACHE_CLEAN_INTERVAL = 0

    DEFAULT_CLUSTER_SIZE = 65536

    QCOW_REFCOUNT_ENTRY_BITS = 3
    QCOW_REFCOUNT_ENTRY_SIZE = 1 << QCOW_REFCOUNT_ENTRY_BITS

    QCOW_L1_ENTRY_BITS = 3
    QCOW_L1_ENTRY_SIZE = 1 << QCOW_L1_ENTRY_BITS

    QCOW_L2_ENTRY_BITS = 3
    QCOW_L2_ENTRY_SIZE = 1 << QCOW_L2_ENTRY_BITS

    QCOW2_OPT_DATA_FILE = "data-file"
    QCOW2_OPT_LAZY_REFCOUNTS = "lazy-refcounts"
    QCOW2_OPT_DISCARD_REQUEST = "pass-discard-request"
    QCOW2_OPT_DISCARD_SNAPSHOT = "pass-discard-snapshot"
    QCOW2_OPT_DISCARD_OTHER = "pass-discard-other"
    QCOW2_OPT_OVERLAP = "overlap-check"
    QCOW2_OPT_OVERLAP_TEMPLATE = "overlap-check.template"
    QCOW2_OPT_OVERLAP_MAIN_HEADER = "overlap-check.main-header"
    QCOW2_OPT_OVERLAP_ACTIVE_L1 = "overlap-check.active-l1"
    QCOW2_OPT_OVERLAP_ACTIVE_L2 = "overlap-check.active-l2"
    QCOW2_OPT_OVERLAP_REFCOUNT_TABLE = "overlap-check.refcount-table"
    QCOW2_OPT_OVERLAP_REFCOUNT_BLOCK = "overlap-check.refcount-block"
    QCOW2_OPT_OVERLAP_SNAPSHOT_TABLE = "overlap-check.snapshot-table"
    QCOW2_OPT_OVERLAP_INACTIVE_L1 = "overlap-check.inactive-l1"
    QCOW2_OPT_OVERLAP_INACTIVE_L2 = "overlap-check.inactive-l2"
    QCOW2_OPT_OVERLAP_BITMAP_DIRECTORY = "overlap-check.bitmap-directory"
    QCOW2_OPT_CACHE_SIZE = "cache-size"
    QCOW2_OPT_L2_CACHE_SIZE = "l2-cache-size"
    QCOW2_OPT_L2_CACHE_ENTRY_SIZE = "l2-cache-entry-size"
    QCOW2_OPT_REFCOUNT_CACHE_SIZE = "refcount-cache-size"
    QCOW2_OPT_CACHE_CLEAN_INTERVAL = "cache-clean-interval"

    l1_initialized = False
    l2_initialized = False
    refcount_table_initialized = False
    refcount_blocks_initialized = False
    l1_table = []
    l2_tables = OrderedDict()
    refcount_table = []
    refcount_blocks = OrderedDict()
    snapshot_table = []
    current_location = 0

    def __init__(self, img_file):
        # Initialize main variables and objects
        self.file = img_file
        self.name = os.path.basename(self.file.name)
        self.physical_size = os.path.getsize(self.file.name)
        self.header = Image.Header(self)
        self.version = self.header.attr['version']
        if self.version == 1:
            self.virtual_size = self.header.attr['size']
            self.cluster_size = 1 << self.header.attr['cluster_bits']
            self.l1_table_offset = self.header.attr['l1_table_offset']
            self.l2_table_size = self.l2_size = 1 << self.header.attr['l2_bits']
            # Specify segments of virtual address
            self.cluster_address_bits = self.header.attr['cluster_bits']
            self.l2_address_bits = self.header.attr['l2_bits']
            self.l1_address_bits = 64 - self.l2_address_bits -\
                self.cluster_address_bits
            
            # Set bit masks for quicker address parsing
            self.l1_address_mask = int('1'*self.l1_address_bits + '0' * self.l2_address_bits + '1' * self.cluster_address_bits, 2)
            self.l2_address_mask = int('0'*self.l1_address_bits + '1' * self.l2_address_bits + '0' * self.cluster_address_bits, 2)
            self.cluster_address_mask = int('0'*self.l1_address_bits + '0' * self.l2_address_bits + '1' * self.cluster_address_bits, 2)

            self.l1_table_entries = self.l1_entries = 1 << self.l1_address_bits
            # ceiling (disk_size / (cluster_size * l2_size))
            self.l1_table_size = math.ceil(
                self.virtual_size / (self.cluster_size * self.l2_size))

        elif self.version >= 2:
            # Map key header attributes to image object
            self.virtual_size = self.header.attr['size']
            self.cluster_size = self.header.attr['cluster_size']
            self.refcount_table_offset = self.header.attr['refcount_table_offset']
            self.l1_table_entries = self.l1_entries = self.header.attr['l1_entries']
            self.l1_table_offset = self.header.attr['l1_table_offset']
            # TODO: Lookup backing file name if present

            # Calculate additional useful parameters
            self.refcount_table_entries = int(
                self.header.attr['refcount_table_clusters'] * self.cluster_size /
                self.QCOW_REFCOUNT_ENTRY_SIZE)

            # refcount_block_entries = (cluster_size * 8 / refcount_bits)
            self.refcount_block_entries = int(
                self.cluster_size * 8 / self.header.attr['refcount_bits'])
            self.refcount_block_size = 1 << self.header.attr['refcount_order'] >> 3
            self.l2_table_size = self.l2_size = 1 << self.header.attr['cluster_bits'] >> 3
            self.l1_table_size = int(
                int((self.l1_entries * self.QCOW_L1_ENTRY_SIZE / self.cluster_size+1)) *
                (self.cluster_size / self.QCOW_L1_ENTRY_SIZE))
            # Specify segments of virtual address
            self.cluster_address_bits = self.header.attr['cluster_bits']
            self.l2_address_bits = self.header.attr['cluster_bits'] - 3
            self.l1_address_bits = 64 - self.l2_address_bits -\
                self.cluster_address_bits

            #self.refcount_blocks = self.parse_refcount_blocks()

    def get_refcount(self, offset):
        refcount_block_index = (offset >> self.header.attr['cluster_bits']) % \
            self.refcount_block_entries
        refcount_table_entry_index = int(
            (offset >> self.header.attr['cluster_bits']) /
            self.refcount_block_entries)
        refcount_table_entry_offset = int(int(
            self.header.refcount_table_offset[2:], 16) +
            refcount_table_entry_index * 8)
        self.file.seek(refcount_table_entry_offset)
        refcount_table_entry = int.from_bytes(self.file.read(8), "big")
        if refcount_table_entry > 0:
            refcount_block_entry_offset = refcount_table_entry + \
                refcount_block_index * self.refcount_block_size
            self.file.seek(refcount_block_entry_offset)
            refcount = int(self.file.read(self.refcount_block_size).hex(), 16)
        else:
            refcount = 0
        return refcount

    def get_refcount_table(self):
        if self.refcount_table_initialized:
            return self.refcount_table
        table = []
        self.file.seek(int(
            self.header.attr['refcount_table_offset'][2:], 16))
        current_bytes = self.file.read(
            8 * self.refcount_table_entries)
        table = [(int(current_bytes[i:i+8].hex(), 16))
                 for i in range(0, len(current_bytes), 8)]

        self.refcount_table = table
        self.refcount_table_initialized = True
        return table

    def get_refcount_table_entry(self, index):
        return self.get_refcount_table()[index]

    def get_refcount_blocks(self):
        if not self.refcount_table_initialized:
            self.parse_refcount_table()
        if self.refcount_blocks_initialized:
            return self.refcount_blocks
        for refcount_table_entry in self.refcount_table:
            self.get_refcount_block(refcount_table_entry)
        self.refcount_blocks_initialized = True
        return self.refcount_blocks

    def get_refcount_block(self, offset):
        if offset in self.refcount_blocks:
            print("Block already loaded")
            return self.refcount_blocks[offset]
        block = []
        self.file.seek(offset)
        current_bytes = self.file.read(
            self.refcount_block_size * self.refcount_block_entries)
        block = [(int(current_bytes[i:i+self.refcount_block_size].hex(), 16))
                 for i in range(0, len(current_bytes), self.refcount_block_size)]
        self.refcount_blocks[offset] = block
        return block

    def get_l1_table(self):
        if self.l1_initialized:
            return self.l1_table
        self.file.seek(int(self.header.attr['l1_table_offset'][2:], 16))
        current_bytes = self.file.read(8 * self.l1_table_size)
        table = [(int(current_bytes[i:i+8].hex(), 16))
                 for i in range(0, len(current_bytes), 8)]
        self.l1_table = table
        self.l1_initialized = True
        return self.l1_table

    def get_l1_entry(self, index):
        return self.get_l1_table()[index]

    def get_l2_tables(self):
        if self.l2_initialized:
            return self.l2_tables
        for l1_table_entry in self.get_l1_table():
            self.get_l2_table(l1_table_entry)
        self.l2_initialized = True
        return self.l2_tables

    def get_l2_table(self, offset):
        if offset in self.l2_tables:
            return self.l2_tables[offset]
        l2_table = []
        l2_table_offset = offset & self.QCOW_L2_OFFSET_MASK
        if l2_table_offset < self.physical_size:
            if offset == 0:
                l2_table = [0 for i in range(self.l2_table_size)]
            else:
                self.file.seek(l2_table_offset)
                current_bytes = self.file.read(8 * self.l2_table_size)
                l2_table = [(int(current_bytes[i:i+8].hex(), 16))
                            for i in range(0, len(current_bytes), 8)]
                self.l2_tables[offset] = l2_table
        else:
            print('Invalid l2 table offset: ', offset)
        return l2_table

    def get_l2_entry(self, l1_index, l2_index):
        l1_entry = self.get_l1_entry(l1_index)
        l2_entry = self.get_l2_table(l1_entry)[l2_index]
        return l2_entry

    def get_l2_entry_by_address(self, virtual_address, address_parts={}):
        if not address_parts:
            address_parts = parse_address(virtual_address)
        l2_entry = self.get_l2_entry(
            address_parts['l1_index'], address_parts['l2_index'])
        return l2_entry

    def parse_l2_entry(self, l2_value):
        l2_parts = {}
        l2_parts['value'] = l2_value
        l2_parts['refcount'] = self.l2_value_to_l2_refcount(l2_value)
        l2_parts['descriptor_type'] = self.l2_value_to_descriptor_type(
            l2_value)
        descriptor = self.l2_value_to_cluster_descriptor(l2_value)
        if l2_parts['descriptor_type']:
            l2_parts['descriptor'] = self.parse_compressed_descriptor(
                descriptor)
        else:
            l2_parts['descriptor'] = self.parse_standard_descriptor(descriptor)
        return l2_parts

    def get_snapshot_table(self):
        if not self.snapshot_table:
            self.file.seek(int(self.header.attr['snapshots_offset'][2:], 16))
            current_bytes = self.file.read(self.cluster_size)
            table = []
            entry_offset = 0
            for i in range(self.header.attr['nb_snapshots']):

                snapshot = OrderedDict()
                snapshot['raw'] = current_bytes[entry_offset:entry_offset + 56]
                snapshot['l1_table_offset'] = int.from_bytes(
                    snapshot['raw'][:8], byteorder='big')
                snapshot['l1_size'] = int.from_bytes(
                    snapshot['raw'][8:12], byteorder='big')
                snapshot['id_str_size'] = int.from_bytes(
                    snapshot['raw'][12:14], byteorder='big')
                snapshot['name_size'] = int.from_bytes(
                    snapshot['raw'][14:16], byteorder='big')
                snapshot['date_sec'] = int.from_bytes(
                    snapshot['raw'][16:20], byteorder='big')
                snapshot['date_nsec'] = int.from_bytes(
                    snapshot['raw'][20:24], byteorder='big')
                snapshot['vm_clock_nsec'] = int.from_bytes(
                    snapshot['raw'][24:32], byteorder='big')
                snapshot['vm_state_size32'] = int.from_bytes(
                    snapshot['raw'][32:36], byteorder='big')
                snapshot['extra_data_size'] = int.from_bytes(
                    snapshot['raw'][36:40], byteorder='big')

                entry_length = 56 + snapshot['id_str_size'] + \
                    snapshot['name_size']
                if entry_length % 8 != 0:
                    entry_length = ((entry_length // 8) + 1) * 8
                snapshot['raw'] = current_bytes[entry_offset:entry_offset+entry_length]
                snapshot['vm_state_size64'] = int.from_bytes(
                    snapshot['raw'][40:48], byteorder='big')
                snapshot['virtual_disk_size64'] = int.from_bytes(
                    snapshot['raw'][48:56], byteorder='big')
                name_start = 56+snapshot['id_str_size']
                padding_start = name_start + snapshot['name_size']
                snapshot['unique_id_string'] = str(
                    snapshot['raw'][56:name_start])
                snapshot['snapshot_name'] = str(
                    snapshot['raw'][name_start:padding_start])
                snapshot['padding'] = snapshot['raw'][padding_start:]
                table.append(snapshot)
                entry_offset += entry_length
            self.snapshot_table = table
        return self.snapshot_table

    def parse_address(self, virtual_address):
        if self.version == 1:
            l1_index = virtual_address >> (64 - self.l1_address_bits)
            l2_index = (virtual_address & self.l2_address_mask) >> self.cluster_address_bits
            partial_cluster_offset = virtual_address & self.cluster_address_mask
        else:
            l1_index = virtual_address >> (64 - self.l1_address_bits)
            l2_index = (virtual_address >> self.cluster_address_bits) % \
                self.l2_table_size
            partial_cluster_offset = virtual_address % self.cluster_size
            
        return {
                'l1_index': l1_index,
                'l2_index': l2_index,
                'partial_cluster_offset': partial_cluster_offset}

    def v_address_to_p_offset(self, virtual_address):
        return self.get_address_metadata(
            virtual_address)['physical_offset']

    def parse_l1_value(self, l1_value):
        l1_parts = {}
        l1_parts['value'] = l1_value
        l1_parts['refcount'] = self.l1_value_to_refcount(l1_value)
        l1_parts['l2_offset'] = self.l1_value_to_l2_offset(l1_value)
        return l1_parts

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

    def seek(self, pos=-1):
        if pos != -1:
            self.current_location = pos
        return self.current_location

    def read(self, qty=1):
        bytes_read = b''
        bytes_remaining = qty
        try:
            start_location = self.current_location
            while bytes_remaining > 0:
                address_metadata = self.get_address_metadata(
                    self.current_location)
                if address_metadata['physical_offset'] > self.physical_size:
                    raise ValueError
                else:
                    if address_metadata['l2']['descriptor_type'] == 0:
                        if address_metadata['physical_offset'] % self.cluster_size == 0:
                            if bytes_remaining >= self.cluster_size:
                                bytes_read += self.read_physical_cluster(
                                    address_metadata['physical_offset'])
                                self.current_location += self.cluster_size
                                bytes_remaining -= self.cluster_size
                            else:
                                bytes_read += self.read_physical_bytes(
                                    address_metadata['physical_offset'],
                                    bytes_remaining)
                                self.current_location += bytes_remaining
                                bytes_remaining -= bytes_remaining
                                # print("Current Location:", self.current_location, "Physical Offset:", physical_offset,
                                #      "Bytes Remaining:", bytes_remaining)
                        else:
                            bytes_until_boundary = self.cluster_size - \
                                self.current_location % self.cluster_size
                            if bytes_remaining >= bytes_until_boundary:
                                partial_byte_count = int(
                                    self.cluster_size -
                                    address_metadata['physical_offset'] %
                                    self.cluster_size)
                                bytes_read += self.read_physical_bytes(
                                    address_metadata['physical_offset'],
                                    partial_byte_count)
                                self.current_location += partial_byte_count
                                bytes_remaining -= partial_byte_count
                            else:
                                bytes_read += self.read_physical_bytes(
                                    address_metadata['physical_offset'],
                                    bytes_remaining)
                                self.current_location += bytes_remaining
                                bytes_remaining -= bytes_remaining
                    else:
                        compressed_data = self.read_physical_bytes(
                            address_metadata['physical_offset'],
                            self.QCOW2_COMPRESSED_SECTOR_SIZE)
                        decompressed_data = zlib.decompress(
                            compressed_data, -zlib.MAX_WBITS,
                            self.QCOW2_COMPRESSED_SECTOR_SIZE)
                        self.current_location += self.QCOW2_COMPRESSED_SECTOR_SIZE
                        bytes_remaining -= self.QCOW2_COMPRESSED_SECTOR_SIZE
                        if bytes_remaining >= self.QCOW2_COMPRESSED_SECTOR_SIZE:
                            bytes_read += decompressed_data
                        else:
                            bytes_read += decompressed_data[:bytes_remaining]
                return bytes_read
        except ValueError:
            print("Reading physical offset at ", address_metadata['physical_offset'], 'exceeds disk size.', self.virtual_size -
                  self.current_location,
                  "bytes remain from current location (",
                  self.current_location, ") Virtual Size:", self.virtual_size, " Physical Size: ", self.physical_size)
            exit(2)

    def read_data(self, f_args):
        data = self.iterate_addresses(
            self.read_range, f_args)
        return data

    def iterate_addresses(self, function, f_args):
        results = []

        if 'increment' not in f_args:
            f_args['increment'] = self.cluster_size

        if 'start' not in f_args:
            f_args['start'] = 0

        if 'stop' not in f_args:
            if f_args['physical_address']:
                f_args['stop'] = self.physical_size
            else:
                f_args['stop'] = self.l1_table_entries * self.l2_table_size * \
                    self.cluster_size

        for address in range(
                f_args['start'],
                f_args['stop'],
                f_args['increment']):
            results.append(function(address, f_args))
        return results

    def read_range(self, address, f_args):
        if f_args['physical_address']:
            results = {'metadata': {'address': address, 'address_parts': 'N/A',
                                    'l1': 'N/A', 'l2': 'N/A', 'physical_offset': address},
                       'data': self.read_physical_bytes(address, f_args['increment'])}
        else:
            metadata = self.get_address_metadata(address)
            if metadata['physical_offset'] == 0:
                results = {'metadata': metadata, 'data': b''}
            else:
                self.seek(address)
                results = {'metadata': metadata,
                           'data': self.read(f_args['increment'])}
        return results

    def get_address_metadata(self, virtual_address):
        metadata = {}
        address_parts = self.parse_address(virtual_address)
        l1_index = address_parts['l1_index']
        l2_index = address_parts['l2_index']
        metadata['address'] = virtual_address
        metadata['address_parts'] = address_parts
        metadata['l1'] = self.parse_l1_value(self.get_l1_entry(l1_index))
        metadata['l2'] = self.parse_l2_entry(
            self.get_l2_entry_by_address(virtual_address, address_parts))
        cluster_offset = metadata['l2']['descriptor']['host_cluster_offset']
        metadata['physical_offset'] = int(
            cluster_offset + (virtual_address % self.cluster_size))
        return metadata

    def l1_value_to_refcount(self, l1_value):
        return (l1_value & self.QCOW_OFLAG_COPIED) >> 63

    def l1_value_to_l2_offset(self, l1_value):
        return (l1_value & ~self.QCOW_OFLAG_COPIED)

    def l2_value_to_cluster_descriptor(self, l2_value):
        return l2_value & self.QCOW_DESCRIPTOR_MASK

    def l2_value_to_descriptor_type(self, l2_value):
        return (l2_value & self.QCOW_OFLAG_COMPRESSED) >> 62

    def l2_value_to_l2_refcount(self, l2_value):
        return (l2_value & self.QCOW_OFLAG_COPIED) >> 63

    def parse_standard_descriptor(self, descriptor):
        read_as_zeros = descriptor & self.QCOW_OFLAG_ZERO
        reserved_lower = descriptor & self.QCOW_DESCRIPTOR_RESERVED_LOWER_MASK >> 1
        host_cluster_offset = descriptor & self.QCOW_DESCRIPTOR_USEABLE_OFFSET_MASK
        reserved_upper = descriptor & self.QCOW_DESCRIPTOR_RESERVED_UPPER_MASK >> 56
        return {
            'value': descriptor,
            'read_as_zeros': read_as_zeros,
            'reserved_lower': reserved_lower,
            'host_cluster_offset': host_cluster_offset,
            'reserved_upper': reserved_upper}

    def parse_compressed_descriptor(self, descriptor):
        # x = 62 - (cluster_bits - 8)
        # Bit  0 - x-1:   Host cluster offset.
        x = 62 - (self.header.attr['cluster_bits'] - 8)
        mask = int('0' * (62-x) + '1' * x, 2)
        host_cluster_offset = descriptor & mask
        # mask = int('1' * (62-x) + '0' * x, 2)
        additional_sectors = descriptor >> x
        return {
            'value': descriptor,
            'host_cluster_offset': host_cluster_offset,
            'additional_sectors': additional_sectors}

    def referenced(self):
        return 1

    def check(self, check_type, f_args={}):
        results = -1
        if check_type == 'consistency':
            results = self.iterate_addresses(
                self.check_consistency, f_args)
        return results

    def check_consistency(self, virtual_address, fargs):
        address_metadata = self.get_address_metadata(virtual_address)
        refcount = self.get_refcount(
            address_metadata['l2']['descriptor']['host_cluster_offset'])
        consistency = []
        # Check for refcount consistency
        if refcount != address_metadata['l1']['refcount'] or \
                refcount != address_metadata['l2']['refcount']:
            consistency.append("Inconsistent_RefCounts")
        # Check if cluster is dereferenced
        if refcount == 0 and \
                address_metadata['l2']['descriptor']['host_cluster_offset'] > 0:
            consistency.append("Dereferenced")
        # Check if cluster is leaked
        if refcount > 0 and \
                address_metadata['l2']['descriptor']['host_cluster_offset'] == 0:
            consistency.append("Dereferenced")
        if len(consistency) == 0:
            consistency.append("Clean")
        return {
            'address': virtual_address,
            'refcount': refcount,
            'address_metadata': address_metadata,
            'consistency': consistency}

    def check_references(self):
        pass

    def comment(self, attr, value):
        if attr in self.header.structure:
            return self.header.comment(attr, value)
        else:
            return Fore.LIGHTBLACK_EX + "N/A" + Style.RESET_ALL

    class Header:
        # 'header attribute name': [attr_offset, attr_size, 'description', 'type']
        v1_structure = {
            'magic': [0, 4, 'QCOW Magic String (QFI\\xfb)', 'string'],
            'version': [4, 4, 'QCOW Version', 'int'],
            'backing_file_offset': [
                8, 8,
                'Offset to backing file name',
                'address'],
            'backing_file_size': [
                16, 4,
                'Size of backing file name in bytes',
                'int'],
            'mtime': [
                20, 4,
                'Not Used',
                'int'],
            'size': [
                24, 8,
                'Virtual Disk Size in bytes',
                'int'],
            'cluster_bits': [
                32, 1,
                'Cluster Bits',
                'int'],
            'l2_bits': [
                33, 1,
                'L2 Bits',
                'int'],
            'crypt_method': [
                34, 4,
                'Encryption (0-None,1-128-bit AES)',
                'int'],
            'UNKNOWN': [
                38, 2,
                'Inconsistency in documentation',
                'int'], 
            'l1_table_offset': [
                40, 8,
                'Offset to L1 Table',
                'address'],
        }
        v2_structure = {
            'magic': [0, 4, 'QCOW Magic String (QFI\\xfb)', 'string'],
            'version': [4, 4, 'QCOW Version', 'int'],
            'backing_file_offset': [
                8, 8,
                'Offset to backing file name',
                'address'],
            'backing_file_size': [
                16, 4,
                'Size of backing file name in bytes',
                'int'],
            'cluster_bits': [
                20, 4,
                'Cluster Bits',
                'int'],
            'size': [
                24, 8,
                'Virtual Disk Size in bytes',
                'int'],
            'crypt_method': [
                32, 4,
                'Encryption (0-None,1-AES,2-LUKS)',
                'int'],
            'l1_entries': [
                36, 4,
                'Entries in the active L1 table',
                'int'],
            'l1_table_offset': [
                40, 8,
                'Offset to L1 Table',
                'address'],
            'refcount_table_offset': [
                48, 8,
                'Offset to RefCount Table',
                'address'],
            'refcount_table_clusters': [
                56, 4,
                'Clusters occupied by RefCount Table',
                'int'],
            'nb_snapshots': [
                60, 4,
                'Number of snapshots',
                'int'],
            'snapshots_offset': [
                64, 8,
                'Offset to first snapshot',
                'address'],
            'incompatible_features': [
                72, 8,
                'Bitmask of incompatible features',
                'bin'],
            'compatible_features': [
                80, 8,
                'Bitmask of compatible features',
                'bin'],
            'autoclear_features': [
                88, 8,
                'Bitmask of auto-clear features',
                'bin'],
            'refcount_order': [
                96, 4,
                'RefCount Block entry bit width (< 6)',
                'int'],
            'header_length': [
                100, 4,
                'Header Length',
                'int']}
        raw = b''
        attr = OrderedDict()

        def __init__(self, img):
            self.img = img
            self.img.file.seek(0)
            self.attr = {}
            self.attr['magic'] = self.img.file.read(
                Image.Header.v1_structure['magic'][1])
            self.attr['version'] = int(self.img.file.read(
                Image.Header.v1_structure['version'][1]).hex(), 16)
            if int(self.attr['version']) == 1:
                self.structure = Image.Header.v1_structure
            elif int(self.attr['version']) >= 2:
                self.structure = Image.Header.v2_structure
            if int(self.attr['version']) >= 3:
                self.img.file.seek(100)
                self.attr['header_length'] = int(img.file.read(
                    self.structure['header_length'][1]).hex(), 16)
            elif int(self.attr['version']) == 2:
                self.attr['header_length'] = 72
            else:
                self.attr['header_length']  = 48
            self.img.file.seek(0)
            self.raw = self.img.file.read(self.attr['header_length'])
            # Parse additional parameters
            self.attr['backing_file_offset'] = self.get_by_name(
                'backing_file_offset')['value']
            self.attr['backing_file_size'] = self.get_by_name(
                'backing_file_size')['value']
            self.attr['cluster_bits'] = self.get_by_name(
                'cluster_bits')['value']
            self.attr['cluster_size'] = 1 << self.attr['cluster_bits']
            self.attr['l2_bits'] = self.get_by_name(
                'l2_bits')['value']
            self.attr['size'] = self.get_by_name(
                'size')['value']
            self.attr['crypt_method'] = self.get_by_name(
                'crypt_method')['value']
            self.attr['l1_entries'] = self.get_by_name(
                'l1_entries')['value']
            self.attr['l1_table_offset'] = self.get_by_name(
                'l1_table_offset')['value']
            self.attr['refcount_table_offset'] = self.get_by_name(
                'refcount_table_offset')['value']
            self.attr['refcount_table_clusters'] = self.get_by_name(
                'refcount_table_clusters')['value']
            self.attr['nb_snapshots'] = self.get_by_name(
                'nb_snapshots')['value']
            self.attr['snapshots_offset'] = self.get_by_name(
                'snapshots_offset')['value']
            if self.attr['version'] >= 3:
                self.attr['incompatible_features'] = self.get_by_name(
                    'incompatible_features')['value']
                self.attr['compatible_features'] = self.get_by_name(
                    'compatible_features')['value']
                self.attr['autoclear_features'] = self.get_by_name(
                    'autoclear_features')['value']
                self.attr['refcount_order'] = self.get_by_name(
                    'refcount_order')['value']
                self.attr['refcount_bits'] = 1 << self.attr['refcount_order']
            else:
                self.attr['incompatible_features'] = '0b0'
                self.attr['compatible_features'] = '0b0'
                self.attr['autoclear_features'] = '0b0'
                self.attr['refcount_order'] = 2
                self.attr['refcount_bits'] = 4

        def __str__(self):
            return "Magic: " + repr(self.attr['magic']) + \
                ", Version: " + repr(self.attr['version']) + \
                ", Header Length: " + repr(self.attr['size'])

        def __repr__(self):
            return {
                'Magic': repr(self.attr['magic']),
                'Version': repr(self.attr['version']),
                'Header Length': repr(self.attr['size'])}

        def get_by_name(self, name):
            attr_raw = b''
            attr_value = 0
            if name in self.structure:
                if self.structure[name][0] < self.attr['header_length']:
                    byte_start = self.structure[name][0]
                    byte_end = self.structure[name][0] + \
                        self.structure[name][1]
                    attr_raw = self.raw[byte_start:byte_end].hex()
                    if self.structure[name][3] == 'int':
                        attr_value = int(attr_raw, 16)
                    elif self.structure[name][3] == 'bin':
                        attr_value = bin(int(attr_raw, 16))
                    elif self.structure[name][3] == 'address':
                        attr_value = str.format('0x{:X}', int(attr_raw, 16))
                    else:
                        attr_value = binascii.unhexlify(attr_raw)
                    attr = {'name': name, 'raw': attr_raw, 'value': attr_value,
                            'description': self.structure[name][2],
                            'start': byte_start,
                            'end': byte_end - 1}
                else:
                    attr = {'name': name, 'raw': 'Header too short (' + name + ')', 'value': '0', 'description': 'Header too short (' + name + ')', 'start': 0,
                            'end': 0}
            else:
                attr = {'name': name, 'raw': 'Invalid attribute',
                        'value': '0', 'description': 'Invalid attribute (' + name + ')', 'start': 0,
                        'end': 0}
            return attr

        def comment(self, attr, value):
            comment = Fore.RED + 'LOGIC ERROR'
            valid = Fore.GREEN + "VALID"
            invalid = Fore.RED + "INVALID"
            if attr == 'magic' and value == b'QFI\xfb':
                comment = valid
            elif attr == 'version' and value in [1, 2, 3]:
                comment = valid
            elif attr == 'backing_file_offset':  # TODO: Add additional checks
                if int(value[2:], 16) > 0:
                    if int(value[2:], 16) % self.cluster_size == 0:
                        comment = Fore.MAGENTA + "HAS BACKING FILE"
                    else:
                        comment = Fore.RED + "MISALIGNED"
                else:
                    comment = Fore.GREEN + "NO BACKING FILE"
            elif attr == 'backing_file_size':
                if (value == 0 and int(
                    self.get_by_name('backing_file_offset')['value'][2:],
                        16) == 0) or \
                        (value > 0 and
                         int(self.get_by_name(
                             'backing_file_offset')['value'][2:], 16) > 0):
                    comment = valid
                else:
                    comment = Fore.RED + \
                        "INCONSISTENT WITH BYTES 16-19"
            elif attr == 'mtime':
                comment = Fore.LIGHTBLACK_EX + 'IGNORED'
            elif attr == 'l2_bits' and value >= 9 and value <= 62:
                comment = valid
            elif attr == 'cluster_bits':
                if self.attr['version'] == 1:
                    if value >= 9 and value <= 62:
                        comment = valid
                else:
                    if value >= 9:
                        comment = valid
            elif attr == 'size' and value > 0:
                comment = valid
            elif attr == 'crypt_method' and value < 3 and value >= 0:  # TODO: Add additional checks
                comment = valid
            elif attr == 'l1_entries' and value >= 0:
                comment = valid
            elif attr == 'l1_table_offset':
                v = int(value[2:], 16)
                if self.attr['version'] == 1:
                    if v > 47:
                        comment = valid
                    else:
                        comment = Fore.RED + "MISALIGNED"
                else:
                    if v > 0 and v % self.attr['cluster_size'] == 0:
                        comment = valid
                    else:
                        comment = Fore.RED + "MISALIGNED"
            elif attr == 'refcount_table_offset':
                v = int(value[2:], 16)
                if v > 0 and v % self.attr['cluster_size'] == 0:
                    comment = valid
                else:
                    comment = Fore.RED + "MISALIGNED"
            elif attr == 'refcount_table_clusters' and value > 0:
                comment = valid
            elif attr == 'nb_snapshots':
                if value > 0:
                    comment = Fore.YELLOW + "HAS SNAPSHOTS"
                else:
                    comment = Fore.GREEN + "NO SNAPSHOTS"
            elif attr == 'snapshots_offset':
                v = int(value[2:], 16)
                if (v == 0 and
                        self.get_by_name('nb_snapshots')['value'] == 0) or \
                        (v > 0 and
                         self.get_by_name('nb_snapshots')['value'] > 0):
                    if v % self.attr['cluster_size'] == 0:
                        comment = valid
                    else:
                        comment = Fore.RED + "MISALIGNED"
                else:
                    comment = Fore.RED + "INCONSISTENT WITH SNAPSHOT COUNT"
            # Version 3+ headers
            elif attr == 'incompatible_features':  # TODO: Add additional checks
                if self.attr['version'] < 3 and int(value, 2) > 0:
                    comment = Fore.RED + "VERSION 3+ ONLY"
                elif self.attr['version'] < 3 and int(value, 2) == 0:
                    comment = Fore.GREEN + 'UNSET'
                else:
                    comment = valid
            elif attr == 'compatible_features':  # TODO: Add additional checks
                if self.attr['version'] < 3 and int(value, 2) > 0:
                    comment = Fore.RED + "VERSION 3+ ONLY"
                elif self.attr['version'] < 3 and int(value, 2) == 0:
                    comment = Fore.GREEN + 'UNSET'
                else:
                    comment = valid
            elif attr == 'autoclear_features':  # TODO: Add additional checks
                if self.attr['version'] < 3 and int(value, 2) > 0:
                    comment = Fore.RED + "VERSION 3+ ONLY"
                elif self.attr['version'] < 3 and int(value, 2) == 0:
                    comment = Fore.GREEN + 'UNSET'
                else:
                    comment = valid
            elif attr == 'refcount_order':
                if self.attr['version'] < 3 and int(value, 2) != 0:
                    comment = Fore.RED + "VERSION 3+ ONLY"
                elif self.attr['version'] < 3 and int(value, 2) == 0:
                    comment = Fore.GREEN + 'UNSET'
                elif self.attr['version'] >= 3 and value < 6 and value > 0:
                    comment = valid
                else:
                    comment = invalid
            elif attr == 'header_length':
                if self.attr['version'] == 1:
                        comment = Fore.RED + 'INCONSISTENT'
                elif self.attr['version'] >= 3:
                    if value == 104:
                        comment = Fore.GREEN + "REGULAR HEADER"
                    elif value > 104:
                        self.img.file.seek(104)
                        next_header = self.img.file.read(4)
                        if int(next_header) > 0:
                            comment = Fore.MAGENTA + "EXTENDED HEADER"
                        else:
                            comment = Fore.RED + "INCONSISTENT EXTENDED HEADER"
                else:
                    if int(value, 2) == 0:
                        comment = Fore.GREEN + 'UNSET'
            elif attr == 'UNKNOWN':
                comment = Fore.LIGHTBLACK_EX + 'UNKNOWN'
            else:
                comment = Fore.RED + 'INCONSISTENT'
                #comment = invalid
            return comment

    def plain_info(self, args):
        formats.plain_helpers.title('INFO')
        table_data = []
        table_data.append(['Filename', Fore.BLUE + self.name])
        table_data.append(['Physical Size', Fore.MAGENTA +
                           str(self.physical_size) + " byte(s)"])
        table_data.append(['Virtual Size', Fore.MAGENTA +
                           str(self.virtual_size) + " byte(s)"])
        table_data.append(['Cluster Size', Fore.MAGENTA +
                           str(self.cluster_size) + " byte(s)"])
        if args.detailed:
            table_data.append(
                ['L1 Table Size', Fore.LIGHTMAGENTA_EX + str(self.l1_table_size)])
            table_data.append(
                ['L2 Table Size', Fore.LIGHTMAGENTA_EX + str(self.l2_table_size)])
            if self.version >= 2:
                table_data.append(
                    ['RefCount Table Entries', Fore.LIGHTMAGENTA_EX + str(self.refcount_table_entries)])
                table_data.append(
                    ['RefCount Block Entries', Fore.LIGHTMAGENTA_EX + str(self.refcount_block_entries)])

        formats.plain_helpers.table(table_data, [25, 45])

    def json_info(self, args):
        info = OrderedDict()
        info['filename'] = self.name
        info['physical_size'] = self.physical_size
        info['virtual_size'] = self.virtual_size
        info['cluster_size'] = self.cluster_size
        if args.detailed:
            info['l1_table_size'] = self.l1_table_size
            info['l2_table_size'] = self.l2_table_size
            if self.version >= 2:
                info['refcount_table_entries'] = self.refcount_table_entries
                info['refcount_block_entries'] = self.refcount_block_entries

        output = OrderedDict()
        output['info'] = info
        return json.dumps(output, indent=2)

    def plain_header(self, args):
        formats.plain_helpers.title('HEADER')
        table_labels = ['Byte(s)', 'Raw (Hex)', 'Value',
                        'Status', 'Description']
        table_data = []
        table_data.append(table_labels)
        for key in self.header.structure:
            attr = self.header.get_by_name(key)
            b = str(attr['start']) + '-' + str(attr['end'])
            r = Fore.CYAN + attr['raw']
            v = Fore.LIGHTCYAN_EX + str(attr['value'])
            s = self.comment(key, attr['value'])
            d = attr['description']
            table_data.append([key, b, r, v, s, d])
        formats.plain_helpers.table(
            table_data, [25, 7, 17, 10, 16, 36], True, True)

    def json_header(self, args):
        header = OrderedDict()
        header['raw'] = repr(self.header.raw)
        for key in self.header.attr:
            if isinstance(self.header.attr[key], bytes):
                header[key] = repr(self.header.attr[key])
            else:
                header[key] = self.header.attr[key]
        output = OrderedDict()
        output['header'] = header
        return json.dumps(output, indent=2)

    def plain_refcount_table(self, args):
        indent = "\t"
        formats.plain_helpers.title('REFCOUNT TABLE')
        table_data = []
        table_data.append(['RefCount Table Offset', Fore.BLUE +
                           self.header.attr['refcount_table_offset']])
        table_data.append(['Cluster Bits', Fore.LIGHTMAGENTA_EX +
                           str(self.header.attr['cluster_bits'])])
        table_data.append(
            ['Cluster Size', Fore.LIGHTMAGENTA_EX + str(self.cluster_size)])
        table_data.append(['RefCount Table Clusters Occupied', Fore.LIGHTMAGENTA_EX +
                           str(self.header.attr['refcount_table_clusters'])])
        table_data.append(
            ['RefCount Table Entry Count', Fore.LIGHTMAGENTA_EX + str(self.refcount_table_entries)])
        table_data.append(
            ['Possible RefCount Table Entries', Fore.LIGHTMAGENTA_EX + str(self.header.attr['refcount_table_clusters']*self.cluster_size)])
        table_data.append(['RefCount Bits', Fore.LIGHTMAGENTA_EX +
                           str(self.header.attr['refcount_bits'])])
        table_data.append(['RefCount Block Entry Count', Fore.LIGHTMAGENTA_EX +
                           str(self.refcount_block_entries)])
        formats.plain_helpers.table(table_data, [35, 10])

        formats.plain_helpers.title('REFCOUNT TABLE ENTRIES')
        if not args.detailed:
            column_count = 4
            row_total = column_count
            for refcount_table_entry_index, refcount_table_entry in enumerate(self.get_refcount_table()):
                indent = "\t"
                refcount_table_entry_offset = (
                    int(self.header.attr['refcount_table_offset'][2:], 16) +
                    refcount_table_entry_index * 8)
                if not args.detailed:
                    if refcount_table_entry > 0 or args.zeros:
                        if refcount_table_entry_index % column_count == 0:
                            print("\n" + Fore.WHITE +
                                  hex(refcount_table_entry_offset) +
                                  " (" + str(refcount_table_entry_index) + "-" +
                                  str(refcount_table_entry_index + row_total-1) + "):  ", end='')
                        if refcount_table_entry == 0:
                            # UNUSED
                            comment = Fore.WHITE
                        elif refcount_table_entry <= self.physical_size:
                            # REFERENCED
                            comment = Fore.MAGENTA
                        else:
                            # OTHER
                            comment = Fore.RED
                        print("\t" + comment + hex(refcount_table_entry), end='')
                else:
                    # TODO:
                    print("Detailed not implemented yet")
        else:
            # TODO:
            print("Detailed not implemented yet")
        print(Style.RESET_ALL)

    def plain_refcount_blocks(self, args):
        indent = "\t"
        line_header = "\n" + indent + Fore.WHITE
        filler = "\t" + Fore.WHITE + '0' * self.refcount_block_size
        formats.plain_helpers.title('REFCOUNT BLOCKS')
        for refcount_table_index, refcount_table_entry in enumerate(self.get_refcount_table()):
            refcount_entry_offset = int(
                self.refcount_table_offset[2:], 16) + refcount_table_index * 8
            column_count = 8
            row_total = int(self.refcount_block_size / 2 * column_count)

            if args.zeros and refcount_table_entry == 0:
                formats.plain_helpers.title(
                    'RefCount Block ' + str(refcount_table_index) + ' (Offset: ' + hex(refcount_entry_offset) + ')')
                refcount_entry_bits = format(
                    refcount_table_entry, '#066b')
                for refcount_block_index in range(self.refcount_block_entries):
                    if refcount_block_index % column_count == 0:
                        print(line_header + '0x000000' +
                              " (" + str(refcount_block_index) + "-" +
                              str(refcount_block_index + row_total-1) + "):  ", end='')
                    print(filler, end='')
            elif refcount_table_entry > 0:
                formats.plain_helpers.title(
                    'RefCount Block ' + str(refcount_table_index) + ' (Offset: ' + hex(refcount_entry_offset) + ')')
                refcount_entry_bits = format(
                    refcount_table_entry, '#066b')
                for refcount_block_index, refcount_block_entry in enumerate(self.get_refcount_block(refcount_table_entry)):
                    refcount_block_entry_offset = refcount_table_entry + \
                        refcount_block_index * self.refcount_block_size
                    if refcount_block_index % column_count == 0:
                        print(line_header + hex(refcount_block_entry_offset) +
                              " (" + str(refcount_block_index) + "-" +
                              str(refcount_block_index + row_total-1) + "):  ", end='')
                    if int(refcount_block_entry) == 0:
                        # UNUSED
                        comment = Fore.WHITE
                    elif int(refcount_block_entry) == 1:
                        # REFERENCED
                        comment = Fore.MAGENTA
                    else:
                        # OTHER
                        comment = Fore.RED
                    print("\t" + comment + hex(refcount_block_entry), end='')

    def plain_l1_table(self, args):
        indent = "\t"
        formats.plain_helpers.title('L1 TABLE')
        table_data = []
        table_data.append(['L1 Table Offset', Fore.BLUE +
                           self.header.attr['l1_table_offset']])
        table_data.append(['Cluster Bits', Fore.LIGHTMAGENTA_EX +
                           str(self.header.attr['cluster_bits'])])
        table_data.append(
            ['Cluster Size', Fore.LIGHTMAGENTA_EX + str(self.cluster_size)])
        table_data.append(
            ['Claimed L1 Table Entry Count', Fore.LIGHTMAGENTA_EX + str(self.l1_table_entries)])
        table_data.append(
            ['Possible L1 Table Entry Count', Fore.LIGHTMAGENTA_EX + str(self.l1_table_size)])
        formats.plain_helpers.table(table_data, [35, 10])

        formats.plain_helpers.title('L1 TABLE ENTRIES')
        column_count = 4
        row_total = column_count
        if args.zeros:
            entry_count = self.l1_table_size
        else:
            entry_count = self.l1_table_entries
        for l1_index, l1_entry in enumerate(self.get_l1_table()):
            indent = "\t"
            l1_entry_offset = int(
                self.l1_table_offset[2:], 16) + l1_index * 8
            if not args.detailed:
                if l1_entry > 0 or args.zeros:
                    if l1_index % column_count == 0:
                        print("\n" + Fore.WHITE +
                              hex(l1_entry_offset) +
                              " (" + str(l1_index) + "-" +
                              str(l1_index + row_total-1) +
                              "):  ", end='')
                    if l1_entry == 0:
                        # UNUSED
                        comment = Fore.WHITE
                    elif l1_entry & self.QCOW_L2_OFFSET_MASK <= self.physical_size:
                        # REFERENCED
                        comment = Fore.MAGENTA
                    else:
                        # OTHER
                        comment = Fore.RED
                    print("\t" + comment + hex(l1_entry), end='')
            else:
                # TODO:
                print("Detailed not implemented yet")
        print(Style.RESET_ALL)

    def plain_l2_tables(self, args):
        indent = "\t"
        formats.plain_helpers.title('L2 TABLES')
        table_data = []
        table_data.append(['L2 Table Count', Fore.LIGHTMAGENTA_EX +
                           str(self.l1_table_size)])
        table_data.append(['L2 Table Size', Fore.LIGHTMAGENTA_EX +
                           str(self.l2_table_size)])
        formats.plain_helpers.table(table_data, [35, 10])
        column_count = 4
        row_total = column_count
        if args.zeros:
            l1_entry_count = len(self.l1_table)
        else:
            l1_entry_count = self.l1_table_entries
        for l1_index, l1_entry in enumerate(self.get_l1_table()):
            indent = "\t"
            print("\n")
            formats.plain_helpers.title('L2 TABLE  #' +
                                        str(l1_index) + ' (L1 Value: ' + hex(l1_entry) + ')')
            if l1_entry == 0 and args.zeros:
                for l2_index in range(self.l2_table_size):
                    l2_entry_offset = int(
                        l1_entry +
                        l2_index * 8)
                    l2_values = self.parse_l2_entry(0)
                    if not args.detailed:
                        if l2_values['value'] > 0 or args.zeros:
                            if l2_index % column_count == 0:
                                print("\n" + Fore.WHITE +
                                      hex(l2_entry_offset) +
                                      " (" + str(l2_index) + "-" +
                                      str(l2_index + row_total - 1) +
                                      "):      ", end='')
                            if l2_values['value'] == 0:
                                # UNUSED
                                comment = Fore.WHITE
                            elif l2_values['descriptor']['host_cluster_offset'] <= \
                                    self.physical_size:
                                # REFERENCED
                                comment = Fore.MAGENTA
                            else:
                                # OTHER
                                comment = Fore.RED
                            print("\t" + comment +
                                  hex(l2_values['value']), end='')
                    else:
                        # TODO:
                        print("Detailed not implemented yet")
            elif l1_entry == 0 and not args.zeros:
                formats.plain_helpers.title(
                    '----NOT ALLOCATED----', color=Fore.LIGHTRED_EX)
            elif l1_entry > 0:
                for l2_index, l2_entry in enumerate(self.get_l2_table(l1_entry)):
                    l2_table_offset = l1_entry & self.QCOW_L2_OFFSET_MASK
                    l2_entry_offset = int(
                        l2_table_offset +
                        l2_index * 8)
                    l2_values = self.parse_l2_entry(l2_entry)
                    if not args.detailed:
                        if l2_values['value'] > 0 or args.zeros:
                            if l2_index % column_count == 0:
                                segment_1 = Fore.WHITE + \
                                    hex(l2_entry_offset)
                                segment_2 = "(" + str(l2_index) + "-" + \
                                    str(l2_index + row_total - 1) + \
                                    "):"
                                print(
                                    "\n" + segment_1 +
                                    segment_2.rjust(25 -
                                                    len(segment_1), ' '), end='')
                            if l2_values['value'] == 0:
                                # UNUSED
                                comment = Fore.WHITE
                            elif l2_values['descriptor']['host_cluster_offset'] <= \
                                    self.physical_size:
                                # REFERENCED
                                comment = Fore.MAGENTA
                            else:
                                # OTHER
                                comment = Fore.RED
                            print("\t" + comment +
                                  hex(l2_values['value']), end='')
                    else:
                        # TODO:
                        print("Detailed not implemented yet")
            print(Style.RESET_ALL)

    def plain_snapshots(self, args):
        if self.version == 1:
            print("Unsupported in QCOW Version 1")
            exit()
        indent = "\t"
        snapshot_count = self.header.attr['nb_snapshots']
        formats.plain_helpers.title('SNAPSHOTS')
        table_data = []
        table_data.append(['Snapshot Table Offset', Fore.BLUE +
                        self.header.attr['snapshots_offset']])
        table_data.append(['Snapshot Count', Fore.BLUE +
                        str(snapshot_count)])
        formats.plain_helpers.table(table_data, [35, 10])

        formats.plain_helpers.title('SNAPSHOT TABLE ENTRIES')
        table_labels = ['L1 Offset', 'L1 Size', 'Snapshot ID', 'Snapshot Name']
        table_data = []
        table_data.append(table_labels)
        for i, snapshot in enumerate(self.get_snapshot_table()):
            l = "Snapshot " + str(i)
            o = format(snapshot['l1_table_offset'], '#016x')
            s = Fore.CYAN + str(snapshot['l1_size'])
            si = Fore.LIGHTCYAN_EX + snapshot['unique_id_string']
            sn = Fore.LIGHTBLUE_EX + snapshot['snapshot_name']
            table_data.append([l, o, s, si, sn])
        formats.plain_helpers.table(
            table_data, [15, 20, 15, 20, 20], True, True)

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

        # Set data read imcrement size
        if args.bytes:
            f_args['increment'] = 1
        elif args.sectors:
            f_args['increment'] = 512
        else:
            f_args['increment'] = self.cluster_size

        if args.all:
            if args.physical_address:
                f_args['stop'] = self.physical_size
            else:
                f_args['stop'] = self.virtual_size#int(self.l1_table_size * self.l2_table_size *
                                 #    self.cluster_size)
        else:
            if args.physical_address:
                f_args['stop'] = int(f_args['start'] +
                                     args.number_of_chunks * f_args['increment'])
            else:
                f_args['stop'] = int(f_args['start'] +
                                     args.number_of_chunks * f_args['increment'])
        if not args.no_metadata:
            # print(args)
            formats.plain_helpers.title('DATA')

        f_args['physical_address'] = args.physical_address

        # Retrieve data chunks
        #data = self.read_data(f_args)

        raw_data = b''
        previous_zeros = False
        for address in range(
                f_args['start'],
                f_args['stop'],
                f_args['increment']):
            #results.append(function(address, f_args)
            chunk = self.read_range(address, f_args)
        #for chunk in data:
            if args.raw:
                raw_data += chunk['data']
            else:
                if chunk['metadata']['physical_offset'] > 0 or args.physical_address:
                    all_zeros = all(v == 0 for v in chunk['data'])
                    if not all_zeros or not args.zeros:
                        if not args.no_metadata:
                            if args.physical_address:
                                formats.plain_helpers.title(
                                    'Phys Addr:' +
                                    format(chunk['metadata']['address'], '#016x') +
                                    ' / File Offset:' + format(chunk['metadata']['physical_offset'], '#016x'))
                            else:
                                if chunk['metadata']['l2']['descriptor_type'] == 0:
                                    chunk_compression = 'No'
                                else:
                                    chunk_compression = 'Yes'
                                formats.plain_helpers.title(
                                    'Virt Addr:' +
                                    format(chunk['metadata']['address'], '#016x') +
                                    ' / File Offset:' + format(chunk['metadata']['physical_offset'], '#016x') +
                                    ' / Compressed: ' + chunk_compression)
                        if not args.no_data:
                            if all_zeros:
                                formats.plain_helpers.title(
                                    'Empty (' + str(len(chunk['data'])) + ' Byte(s)', filler='*', color=Fore.LIGHTRED_EX)
                                previous_zeros = True
                            else:
                                formats.plain_helpers.data_table(
                                    chunk['metadata']['address'], chunk['data'])
                                previous_zeros = False

        print(Style.RESET_ALL)
        if args.raw:
            print(raw_data)

    def plain_map(self, args):
        formats.plain_helpers.title('Disk Image Map')
        table_labels = ['Start Address', 'Size', 'Description']
        table_data = []
        # Format as hex format(i, '#016x')
        # Add Header
        table_data.append(
            [format(0, '#016x') + ' (0)', self.header.attr['header_length'], 'Header'])

        if self.version > 1:
            if int(self.header.attr['snapshots_offset'], 16) != 0:
                # Add Snaptshot Table
                color = Fore.LIGHTRED_EX
                item_address = format(int(self.header.attr['snapshots_offset'], 16), '#016x') + ' (' + str(int(
                    self.header.attr['snapshots_offset'], 16)) + ')'
                table_data.append([item_address, color +
                                str(self.cluster_size), color + 'Snapshot Table'])

                # Add Snapshot Entries
                color = Fore.LIGHTRED_EX
                for entry in self.get_snapshot_table():
                    item_address = format(entry['l1_table_offset'], '#016x') + ' (' + str(
                        entry['l1_table_offset']) + ')'
                    table_data.append([item_address, color +
                                    str(self.l1_table_size), color + 'Snapshot L1 Table'])

        # Add L1 Table
        color = Fore.MAGENTA
        item_address = format(int(self.header.attr['l1_table_offset'], 16), '#016x') + ' (' + str(int(
            self.header.attr['l1_table_offset'], 16)) + ')'
        table_data.append([item_address, color +
                           str(self.cluster_size), color + 'L1 Table'])

        # Add L2 Tables
        color = Fore.LIGHTMAGENTA_EX
        for l1_index, l1_table_entry in enumerate(self.get_l1_table()):
            l2_offset = l1_table_entry & self.QCOW_L2_OFFSET_MASK
            if l2_offset:
                item_address = format(l2_offset, '#016x') + \
                    ' (' + str(l2_offset) + ')'
                table_data.append(
                    [item_address, color + str(self.l2_table_size), color + 'L2 Table #' + str(l1_index)])

        if self.version > 1:
            # Add RefCount Table
            color = Fore.CYAN
            item_address = format(int(self.header.attr['refcount_table_offset'], 16), '#016x') + ' (' + str(int(
                self.header.attr['refcount_table_offset'], 16)) + ')'
            table_data.append([item_address, color +
                            str(self.cluster_size), color + 'RefCount Table'])

            # Add RefCount Blocks
            color = Fore.LIGHTCYAN_EX
            for refcount_index, refcount_block_offset in enumerate(self.get_refcount_table()):
                if refcount_block_offset:
                    item_address = format(
                        refcount_block_offset, '#016x') + ' (' + str(refcount_block_offset) + ')'
                    table_data.append(
                        [item_address, color + str(self.cluster_size), color + 'RefCount Block #' + str(refcount_index)])

        if args.detailed:
            # Add Data
            color = Fore.BLUE
            for l1_index, l1_table_entry in enumerate(self.get_l1_table()):
                if l1_table_entry != 0:
                    for l2_index, l2_entry in enumerate(self.get_l2_table(l1_table_entry)):
                        data_offset = self.parse_l2_entry(
                            l2_entry)['descriptor']['host_cluster_offset']
                        if data_offset:
                            item_address = format(
                                data_offset, '#016x') + ' (' + str(data_offset) + ')'
                            table_data.append([item_address, color + str(self.cluster_size),
                                               color + 'Data Block ' + str(l1_index) + '-' + str(l2_index)])
            print()
        # Sort data by offset
        #table_data.sort()
        table_data.sort(key = lambda x: x[0])
        table = []
        table.append(table_labels)
        table += table_data
        formats.plain_helpers.table(table, [35, 10, 25], True, False)

    def get_info(self, args):
        if args.format == 'plain':
            self.plain_info(args)
            if args.all or args.detailed:
                self.plain_header(args)
            if args.all:
                self.plain_refcount_table(args)
                self.plain_refcount_blocks(args)
                self.plain_l1_table(args)
                self.plain_l2_tables(args)
        elif args.format == 'json':
            output = OrderedDict()
            output.update(json.JSONDecoder(
                object_pairs_hook=OrderedDict).decode(self.json_info(args)))
            output.update(json.JSONDecoder(
                object_pairs_hook=OrderedDict).decode(self.json_header(args)))
            print(json.dumps(output, indent=2))
        # elif args.format == 'xml':
        #    self.xml_info(args)
        #    self.xml_header(args)
        #    if args.all:
        #        self.xml_refcount_table(args)
        #        self.xml_refcount_blocks(args)
        #        self.xml_l1_table(args)
        #        self.xml_l2_tables(args)

    def get_metadata(self, args):
        if args.format == 'plain':
            self.plain_header(args)
        elif args.format == 'json':
            print(self.json_header(args))

    def get_tables(self, args):
        if args.format == 'plain':
            # For version 2+ only
            if self.version > 1:
                if args.all or args.primary or not (args.all or args.primary or args.secondary):
                    if args.raw:
                        print(self.get_refcount_table())
                    else:
                        self.plain_refcount_table(args)
                if args.all or args.secondary:
                    if args.raw:
                        print(self.get_refcount_blocks())
                    else:
                        self.plain_refcount_blocks(args)

            # L1 and L2 for all versions
            if args.all or args.primary or not (args.all or args.primary or args.secondary):
                if args.raw:
                    print(self.get_l1_table())
                else:
                    self.plain_l1_table(args)

            if args.all or args.secondary:
                if args.raw:
                    print(self.get_l2_tables)
                else:
                    self.plain_l2_tables(args)

    def get_map(self, args):
        if args.format == 'plain':
            self.plain_map(args)
        elif args.format == 'json':
            print('Not Yet Implemented')

    def get_snapshots(self, args):
        if args.format == 'plain':
            self.plain_snapshots(args)
        elif args.format == 'json':
            print("Not Yet Implemented")
        elif args.format == 'xml':
            print("Not Yet Implemented")

    def get_data(self, args, f_args={}):
        # if not args.no_metadata:
        #    self.plain_header(args)
        self.plain_data(args)

    def get_check(self, args, f_args={}):
        self.plain_info(args)
        self.plain_header(args)
        l2_bits = self.header.cluster_bits - 3
        l1_bits = 64 - l2_bits - self.header.cluster_bits
        i = 0
        clean = []
        inconsistent = []
        dereferenced = []
        leaked = []
        results = self.check('consistency')
        # print(consistency_results)
        for result in results:
            if "Clean" in result['consistency']:
                clean.append(result)
            if "Inconsistent" in result['consistency']:
                inconsistent.append(result)
            if "Dereferenced" in result['consistency']:
                dereferenced.append(result)
            if "Leaked" in result['consistency']:
                leaked.append(result)
            i += 1
        if args.all:
            formats.plain_helpers.title('Inconsistent Clusters')
            print(inconsistent)
        if args.all or args.dereferenced:
            formats.plain_helpers.title('Dereferenced Clusters')
            print(dereferenced)
        if args.all or args.leaks:
            formats.plain_helpers.title('Leaked Clusters')
            print(leaked)

    def mount(self, args):
        print("Not Yet Implemented")

    def unmount(self, args):
        print("Not Yet Implemented")
