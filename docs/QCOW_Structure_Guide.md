# QCOW File Structure (Versions 1, 2 & 3)

This document is intended as a consolidated reference for the various versions of QCOW disk image formats. It is based on information from a variety of sources. The referenced materials are listed at the end.

## QCOW Header
Each QCOW file begins with a header, in big endian format, as follows:

| Bytes | Name | Description | Note |
|-|-|-|-|
| 0 - 3 | `magic` | (uint32_t) QCOW magic string | **"QFI\xfb"** |
| 4 - 7 | `version` | (uint32_t) Version number | Valid values are 2 and 3 |
| 8 - 15 | `backing_file_offset` | (uint64_t) Offset into the image file at which the backing file name is stored (NB: The string is not null terminated). | 0 if the image doesn't have a backing file.|
| 16 - 19 | `backing_file_size` | (uint32_t) Length of the backing file name in bytes. Must not be longer than 1023 bytes. | Undefined if the image doesn't have a backing file.|
| 20 - 23 | `cluster_bits` | (uint32_t) Number of bits that are used for addressing an offset within a cluster (1 << cluster_bits is the cluster size). Must not be less than 9 (i.e. 512 byte clusters).|Qemu as of today has an implementation limit of 2 MB as the maximum cluster size and won't be able to open images with larger cluster sizes.|
| 24 - 31 | `size` | (uint64_t) Virtual disk size in bytes. | Qemu has an implementation limit of 32 MB as the maximum L1 table size.  With a 2 MB cluster size, it is unable to populate a virtual cluster beyond 2 EB (61 bits); with a 512 byte cluster size, | it is unable to populate a virtual size larger than 128 GB (37 bits).  Meanwhile, L1/L2 table layouts limit an image to no more than 64 PB (56 bits) of populated clusters, and an image may hit other limits first (such as a file system's maximum size).|
| 32 - 35 | `crypt_method` | (uint32_t) | **0** for no encryption<br/>**1** for AES encryption<br/>**2** for LUKS encryption|
| 36 - 39 | `l1_size` | (uint32_t) Number of entries in the active L1 table|
| 40 - 47 | `l1_table_offset` | (uint64_t) Offset into the image file at which the active L1 table starts. | Must be aligned to a cluster boundary.|
| 48 - 55 | `refcount_table_offset` | (uint64_t)  Offset into the image file at which the refcount table starts. | Must be aligned to a cluster boundary.|
| 56 - 59 | `refcount_table_clusters` | (uint32_t)  Number of clusters that the refcount table occupies|
| 60 - 63 | `nb_snapshots` | (uint32_t) Number of snapshots contained in the image |
| 64 - 71 | `snapshots_offset` | (uint64_t) Offset into the image file at which the snapshot table starts. | Must be aligned to a cluster boundary. |

*For **version 3** or higher, the header has the following additional fields. For **version 2**, the values are assumed to be zero, unless specified otherwise in the description of a field.*

| Bytes | Name | Description | Note |
|-|-|-|-|
| 72 -  79 | `incompatible_features` | Bitmask of incompatible features. | An implementation must fail to open an image if an unknown bit is set. |
|-| Bit 0: `Dirty bit` | If this bit is set then refcounts may be inconsistent, make sure to scan L1/L2 tables to repair refcounts before accessing the image.|
|-| Bit 1: `Corrupt bit` | If this bit is set then any data structure may be corrupt and the image must not be written to (unless for regaining consistency).|
|-| Bit 2: `External data file bit` | If this bit is set, an external data file is used. Guest clusters are then stored in the external data file. For such images, clusters in the external data file are not refcounted. The offset field in the Standard Cluster Descriptor must match the guest offset and neither compressed clusters nor internal snapshots are supported. | An External Data File Name header extension may be present if this bit is set.
|-| Bits 3-63: `Reserved` | set to 0|
| 80 -  87 | `compatible_features` | Bitmask of compatible features. An implementation can safely ignore any unknown bits that are set.|
|-| Bit 0: `Lazy refcounts bit` | If this bit is set then lazy refcount updates can be used.  This means marking the image file dirty and postponing refcount metadata updates.|
|-| Bits 1-63: `Reserved` | set to 0 |
| 88 - 95 | `autoclear_features` | Bitmask of auto-clear features. An implementation may only write to an image with unknown auto-clear features if it clears the respective bits from this field first. |
|-| Bit 0: `Bitmaps extension bit` | This bit indicates consistency for the bitmaps extension data. | It is an error if this bit is set without the bitmaps extension present.</br>If the bitmaps extension is present but this bit is unset, the bitmaps extension data must be considered inconsistent.|
|-| Bit 1: `Consistent Standalone Flag` | If this bit is set, the external data file can be read as a consistent standalone raw image without looking at the qcow2 metadata. | Setting this bit has a performance impact for some operations on the image (e.g. writing zeros requires writing to the data file instead of only setting the zero flag in the L2 table entry) and conflicts with backing files.</br>This bit may only be set if the External Data File bit (incompatible feature bit 1) is also set.|
|-| Bits 2-63:  `Reserved` | set to 0 |
| 96 - 99 | `refcount_order` | Describes the width of a reference count block entry (width in bits: refcount_bits = 1 << refcount_order). For version 2 images, the order is always assumed to be 4 (i.e. refcount_bits = 16). | This value may not exceed 6 (i.e. refcount_bits = 64). |
| 100 - 103 | `header_length` | Length of the header structure in bytes. For version 2 images, the length is always assumed to be 72 bytes.|

## QCOW Disk Image Structure
```
+================================================================+
|   Header                                                       |
|       Location: Address 0                                      |
|       Size: 72 Bytes / 0-71 (Version 1 & 2)                    |
|       Size: 104 Bytes / 0-103 (Version 3)                      |
|================================================================|
|   Optional Header Extensions (Version 3 Only)                  |
|       Location: Address 104                                    |
|       Size: 8+ Bytes (Padded to multiple of 8 bytes)           |
|       Types:                                                   |
|           String / Feature / Bitmaps / Full Disk Encryption    |
|================================================================|
|   L1 Table (Must align to cluster boundary)                    |
|       Location: Set by Bytes 40-47 of header                   |
|       Size: 1+ * cluster size                                  |
|----------------------------------------------------------------|
|   L1 Table Entry                                               |
|       Size: 8 bytes                                            |
|       Note: Contains file offset to L2 Table                   |
|6       5       4       4       3       2      1                |
|3       6       8       0       2       4      6       8       0|
|!.......!.......!.......!.......!.......!......!.......!.......!|
|*00000000<--------Bits 55 to 9: L2 Table Offset-------->00000000|
|================================================================|
|   L2 Table (Must align to cluster boundary)                    |
|       Location: Determined by corresponding L1 Table Entry     |
|       Size: cluster size                                       |
|----------------------------------------------------------------|
|   L2 Table Entry                                               |
|       Size: 8 bytes                                            |
|       Note: Contains data cluster descriptor                   |
|       Example Descriptor:                                      |
|6       5       4       4       3       2      1                |
|3       6       8       0       2       4      6       8       0|
|!.......!.......!.......!.......!.......!......!.......!.......!|
|*C0000000<------Bits 55 to 9: Data Cluster Offset------>00000000|
|================================================================|
|   ...                                                          |
|   Additional L2 Tables (Must align to cluster boundary)        |
|   ...                                                          |
|================================================================|
|   RefCount Table (Must align to cluster boundary)              |
|       Location: Set by Bytes 48 - 55 of header                 |
|       Size: cluster size * Header Bytes 56-59                  |
|       Note: Can cover multiple contiguous clusters             |
|----------------------------------------------------------------|
|   RefCount Table Entry                                         |
|       Size: 8 bytes                                            |
|       Note: Contains file offset to refcount block             |
|       Example Entry:                                           |
|6       5       4       4       3       2      1                |
|3       6       8       0       2       4      6       8       0|
|!.......!.......!.......!.......!.......!......!.......!.......!|
|<-------Bits 63 to 9: RefCount Block Offset------------>00000000|
|================================================================|
|   RefCount Block  (Must align to cluster boundary)             |
|       Location: Determined by offset in RefCount Table         |
|       Size: cluster size                                       |
|----------------------------------------------------------------|
|   RefCount Block Entry                                         |
|       Size: Calculated by 1 << refcount_order  ( size in bits) |
|       Note: Contains reference count of a data cluster         |
|       Example Entry: (If refcount_order=4 then size is 16 bits)|
|           1                                                    |
|           5      8       0                                     |
|           !......!.......!                                     |
|           <00000000000001>                                     |
|================================================================|
|   ...                                                          |
|   Additional RefCount Blocks                                   |
|   ...                                                          |
|================================================================|
|   LUKS Partition Header (Encrypted Disks Only)                 |
|----------------------------------------------------------------|
|        LUKS Key Material 1                                     |
|----------------------------------------------------------------|
|        LUKS Key Material 2                                     |
|----------------------------------------------------------------|
|        LUKS Key Material ...                                   |
|================================================================|
|   ...                                                          |
|   Data Clusters                                                |
|   ...                                                          |
|================================================================|
|   Snapshots Table (Optional)                                   |
|----------------------------------------------------------------|
|   ...                                                          |
|   Snapshots Table Entries                                      |
|   ...                                                          |
|================================================================|
```

## Host cluster management

Qcow manages the allocation of host clusters by maintaining a reference count for each host cluster. A refcount of **0** means that the cluster is **free**, **1** means that it is **used**, and **>= 2** means that it is **used and any write access must perform a COW (copy on write) operation**.

**The refcounts are managed in a two-level table.** The first level is called refcount table and has a variable size (which is stored in the header). The refcount table can cover multiple clusters, however it needs to be contiguous in the image file.

It contains pointers to the second level structures which are called refcount blocks and are exactly one cluster in size.

Although a large enough refcount table can reserve clusters past 64 PB
(56 bits) (assuming the underlying protocol can even be sized that large), note that some qcow2 metadata such as L1/L2 tables must point
to clusters prior to that point.

**Note:** Qemu has an implementation limit of 8 MB as the maximum refcount
table size.  With a 2 MB cluster size and a default refcount_order of
4, it is unable to reference host resources beyond 2 EB (61 bits); in
the worst case, with a 512 cluster size and refcount_order of 6, it is
unable to access beyond 32 GB (35 bits).

Given an offset into the image file, the refcount of its cluster can be
obtained as follows:
```
    refcount_block_entries = (cluster_size * 8 / refcount_bits)

    refcount_block_index = (offset / cluster_size) % refcount_block_entries
    refcount_table_index = (offset / cluster_size) / refcount_block_entries

    refcount_block = load_cluster(refcount_table[refcount_table_index]);
    return refcount_block[refcount_block_index];
```

### RefCount Table Entry Structure

| Bit(s) | Description | Note |
|-|-|-|
| 0 -  8 | `Reserved` | Set to 0|
| 9 - 63 | `RefCount Block Offset` | Bits 9-63 of the offset into the image file at which the refcount block starts. Must be aligned to a cluster boundary.</br>If this is 0, the corresponding refcount block has not yet been allocated. All refcounts managed by this refcount block are 0.|

### RefCount Block Entry Structure

x = refcount_bits - 1

| Bit(s) | Description | Note |
|-|-|-|
| 0 -  x | `Reference Count` | Reference count of the cluster. If refcount_bits implies a sub-byte width, note that bit 0 means the least significant bit in this context.


## Cluster Mapping

Just as for refcounts, qcow uses a two-level structure for the mapping of
guest clusters to host clusters. They are called L1 and L2 table.

The L1 table has a variable size (stored in the header) and may use multiple
clusters, however it must be contiguous in the image file. L2 tables are
exactly one cluster in size.

The L1 and L2 tables have implications on the maximum virtual file
size; for a given L1 table size, a larger cluster size is required for
the guest to have access to more space.  Furthermore, a virtual
cluster must currently map to a host offset below 64 PB (56 bits)
(although this limit could be relaxed by putting reserved bits into
use).  Additionally, as cluster size increases, the maximum host
offset for a compressed cluster is reduced (a 2M cluster size requires
compressed clusters to reside below 512 TB (49 bits), and this limit
cannot be relaxed without an incompatible layout change).

Given an offset into the virtual disk, the offset into the image file can be obtained as follows:
```
    l2_entries = (cluster_size / sizeof(uint64_t))

    l2_index = (offset / cluster_size) % l2_entries
    l1_index = (offset / cluster_size) / l2_entries

    l2_table = load_cluster(l1_table[l1_index]);
    cluster_offset = l2_table[l2_index];

    return cluster_offset + (offset % cluster_size)
```

### L1 Table Entry Structure

| Bit(s) | Description | Note |
|-|-|-|
| 0 -  8 | `Reserved` | Set to 0 |
| 9 - 55 | `L2 Table Offset` | Bits 9-55 of the offset into the image file at which the L2 table starts. Must be aligned to a cluster boundary. | If the offset is 0, the L2 table and all clusters described by this L2 table are unallocated.|
| 56 - 62 | `Reserved` | Set to 0|
| 63 | `Used Flag` | **0** for an L2 table that is unused or requires COW</br>**1** if its refcount is exactly one. This information is only accurate in the active L1 table.|

### L2 Table Entry Structure

| Bit(s) | Description | Note |
|-|-|-|
|0 -  61 | `Cluster descriptor` |
| 62 | `Compressed Flag` | **0** for standard clusters</br>**1** for compressed clusters |
| 63 | `Used Flag` | **0** for clusters that are unused, compressed or require COW.</br>**1** for standard clusters whose refcount is exactly one.| This information is only accurate in L2 tables that are reachable from the active L1 table.</br> With external data files, all guest clusters have an implicit refcount of 1 (because of the fixed host = guest mapping for guest cluster offsets), so this bit should be 1 for all allocated clusters.|

#### Standard Cluster Descriptor Structure

| Bit(s) | Description | Note |
|-|-|-|
| 0 | `Zeros Flag` | If set to 1, the cluster reads as all zeros. The host cluster offset can be used to describe a preallocation, but it won't be used for reading data from this cluster, nor is data read from the backing file if the cluster is unallocated.</br> With version 2, this is always 0.|
| 1 -  8 | `Reserved` | Set to 0|
| 9 - 55 | `Cluster Offset` | Must be aligned to a cluster boundary. If the offset is 0 and bit 63 is clear, the cluster is unallocated. The offset may only be 0 with bit 63 set (indicating a host cluster offset of 0) when an external data file is used.|
| 56 - 61 | `Reserved` | Set to 0|

#### Compressed Clusters Descriptor Structure

offset_bits = 62 - (cluster_bits - 8)

| Bit(s) | Description | Note |
|-|-|-|
|0 - offset_bits-1 | `Host cluster offset` | This is usually _not_ aligned to a cluster or sector boundary!  If cluster_bits is small enough that this field includes bits beyond 55, those upper bits must be set to 0.|
| offset_bits - 61 | `Additional Sectors` | Number of additional 512-byte sectors used for the compressed data, beyond the sector containing the offset in the previous field. Some of these sectors may reside in the next contiguous host cluster.</br> Note that the compressed data does not necessarily occupy all of the bytes in the final sector; rather, decompression stops when it has produced a cluster of data.</br> Another compressed cluster may map to the tail of the final sector used by this compressed cluster.|

If a cluster is unallocated, read requests shall read the data from the backing
file (except if bit 0 in the Standard Cluster Descriptor is set). If there is
no backing file or the backing file is smaller than the image, they shall read
zeros for all parts that are not covered by the backing file.


## Snapshots

qcow2 supports internal snapshots. Their basic principle of operation is to
switch the active L1 table, so that a different set of host clusters are
exposed to the guest.

When creating a snapshot, the L1 table should be copied and the refcount of all
L2 tables and clusters reachable from this L1 table must be increased, so that
a write causes a COW and isn't visible in other snapshots.

When loading a snapshot, bit 63 of all entries in the new active L1 table and
all L2 tables referenced by it must be reconstructed from the refcount table
as it doesn't need to be accurate in inactive L1 tables.

A directory of all snapshots is stored in the snapshot table, a contiguous area
in the image file, whose starting offset and length are given by the header
fields snapshots_offset and nb_snapshots. The entries of the snapshot table
have variable length, depending on the length of ID, name and extra data.

### Snapshot Table Entry Structure

| Bytes | Description | Note |
|-|-|-|
| 0 -  7 | `l1_table_offset` | (uint64_t) Offset into the image file at which the L1 table for the snapshot starts. Must be aligned to a cluster boundary.|
| 8 - 11 | `l1_size` | (uint32_t) Number of entries in the L1 table of the snapshots.|
| 12 - 13 | `id_str_size` | (uint16_t) Length of the unique ID string describing the snapshot.|
| 14 - 15 | `name_size` | (uint16_t) Length of the name of the snapshot|
| 16 - 19 | `date_sec` | (uint32_t) Time at which the snapshot was taken in seconds since the Epoch.|
| 20 - 23 | `date_nsec` | (uint32_t) Subsecond part of the time at which the snapshot was taken in nanoseconds. |
| 24 - 31 | `vm_clock_nsec` | (uint64_t) Time that the guest was running until the snapshot was taken in nanoseconds. |
| 32 - 35 | `vm_state_size (32-bit)` | (uint32_t) Size of the VM state in bytes. 0 if no VM state is saved.</br>If there is VM state, it starts at the first cluster described by first L1 table entry that doesn't describe a regular guest cluster (i.e. VM state is stored like guest disk content, except that it is stored at offsets that are larger than the virtual disk presented to the guest).|
| 36 - 39 | `extra_data_size` | (uint32_t) Size of extra data in the table entry (used for future extensions of the format).|

#### Variable:   Extra data for future extensions. Unknown fields must be ignored. Currently defined are (offset relative to snapshot table entry)

| Bytes | Description | Note |
|-|-|-|
| 40 - 47 | `vm_state_size (64-bit)` | (uint64_t) Size of the VM state in bytes. 0 if no VM state is saved. If this field is present, the 32-bit value in bytes 32-35 is ignored.|
| 48 - 55 | `Virtual Disk Size` | (uint64_t) Virtual disk size of the snapshot in bytes.|

#### Version 3 images must include extra data at least up to byte 55.

| Bytes | Description | Note |
|-|-|-|
| variable | `Unique ID String` | Unique ID string for the snapshot (not null terminated)|
| variable | `Snapshot Name` | Name of the snapshot (not null terminated)|
| variable | `Padding` | Padding to round up the snapshot table entry size to the next multiple of 8.|

## Bitmaps

As mentioned above, the bitmaps extension provides the ability to store bitmaps
related to a virtual disk. This section describes how these bitmaps are stored.

All stored bitmaps are related to the virtual disk stored in the same image, so
each bitmap size is equal to the virtual disk size.

Each bit of the bitmap is responsible for a strictly defined range of the virtual
disk. For bit number bit_num the corresponding range (in bytes) will be:

    [bit_num * bitmap_granularity .. (bit_num + 1) * bitmap_granularity - 1]

Granularity is a property of the concrete bitmap, see below.

### Bitmap Directory

Each bitmap saved in the image is described in a bitmap directory entry. The
bitmap directory is a contiguous area in the image file, whose starting offset
and length are given by the header extension fields bitmap_directory_offset and
bitmap_directory_size. The entries of the bitmap directory have variable
length, depending on the lengths of the bitmap name and extra data.

### Bitmap Directory Entry Structure

| Bytes | Description | Note |
|-|-|-|
| 0 -  7 | `bitmap_table_offset` | Offset into the image file at which the bitmap table (described below) for the bitmap starts. Must be aligned to a cluster boundary.|
| 8 - 11 | `bitmap_table_size` | Number of entries in the bitmap table of the bitmap.|
| 12 - 15 | `flags` | ***Bit 0:*** in_use - The bitmap was not saved correctly and may be inconsistent. Although the bitmap metadata is still well-formed from a qcow2 perspective, the metadata (such as the auto flag or bitmap size) or data contents may be outdated.</br>***Bit 1:*** auto - The bitmap must reflect all changes of the virtual disk by any application that would write to this qcow2 file (including writes, snapshot switching, etc.). The type of this bitmap must be 'dirty tracking bitmap'.</br>***Bit 2:*** extra_data_compatible - This flags is meaningful when the extra data is unknown to the software (currently any extra data is unknown to Qemu). If it is set, the bitmap may be used as expected, extra data must be left as is. If it is not set, the bitmap must not be used, but both it and its extra data be left as is.</br>***Bits 3 - 31*** are reserved and must be 0.|
| 16 | `type` | This field describes the sort of the bitmap.</br>Values:</br>***1:*** Dirty tracking bitmap</br>***Values 0, 2 - 255*** are reserved.|
| 17 | `granularity_bits` |  Granularity bits. Valid values: 0 - 63.</br>***Note:*** Qemu currently supports only values 9 - 31.</br>Granularity is calculated as granularity = 1 << granularity_bits</br>A bitmap's granularity is how many bytes of the image accounts for one bit of the bitmap.|
| 18 - 19 | `name_size` |  Size of the bitmap name. Must be non-zero.</br>***Note:*** Qemu currently doesn't support values greater than 1023.|
| 20 - 23 | `extra_data_size` | Size of type-specific extra data.</br>For now, as no extra data is defined, extra_data_size is reserved and should be zero. If it is non-zero the behavior is defined by extra_data_compatible flag.|
| variable | `extra_data` | Extra data for the bitmap, occupying extra_data_size bytes.</br>Extra data must never contain references to clusters or in some other way allocate additional clusters.|
| variable | `name` | The name of the bitmap (not null terminated), occupying name_size bytes. Must be unique among all bitmap names within the bitmaps extension.|
| variable | `Padding` | Padding to round up the bitmap directory entry size to the next multiple of 8. All bytes of the padding must be zero.|


### Bitmap Table

Each bitmap is stored using a one-level structure (as opposed to two-level
structures like for refcounts and guest clusters mapping) for the mapping of
bitmap data to host clusters. This structure is called the bitmap table.

Each bitmap table has a variable size (stored in the bitmap directory entry)
and may use multiple clusters, however, it must be contiguous in the image
file.

#### Bitmap Table Entry Structure

| Bit(s) | Description | Note |
|-|-|-|
| 0 | `Reserved` | Reserved and must be zero if bits 9 - 55 are non-zero.</br>If bits 9 - 55 are zero:</br>0: Cluster should be read as all zeros.</br>1: Cluster should be read as all ones.|
| 1 - 8 | `Reserved` | Reserved and must be zero.|
| 9 - 55 | `Host Cluster Offset` | Bits 9 - 55 of the host cluster offset. Must be aligned to a cluster boundary. If the offset is 0, the cluster is unallocated; in that case, bit 0 determines how this cluster should be treated during reads.|
| 56 - 63 | `Reserved` | Reserved and must be zero.|


### Bitmap Data

As noted above, bitmap data is stored in separate clusters, described by the
bitmap table. Given an offset (in bytes) into the bitmap data, the offset into
the image file can be obtained as follows:
```
    image_offset(bitmap_data_offset) =
        bitmap_table[bitmap_data_offset / cluster_size] +
            (bitmap_data_offset % cluster_size)
```

This offset is not defined if bits 9 - 55 of bitmap table entry are zero (see
above).

Given an offset byte_nr into the virtual disk and the bitmap's granularity, the
bit offset into the image file to the corresponding bit of the bitmap can be
calculated like this:
```
    bit_offset(byte_nr) =
        image_offset(byte_nr / granularity / 8) * 8 +
            (byte_nr / granularity) % 8
```

If the size of the bitmap data is not a multiple of the cluster size then the
last cluster of the bitmap data contains some unused tail bits. These bits must
be zero.


### Dirty Tracking Bitmaps

Bitmaps with 'type' field equal to one are dirty tracking bitmaps.

When the virtual disk is in use dirty tracking bitmap may be 'enabled' or
'disabled'. While the bitmap is 'enabled', all writes to the virtual disk
should be reflected in the bitmap. A set bit in the bitmap means that the
corresponding range of the virtual disk (see above) was written to while the
bitmap was 'enabled'. An unset bit means that this range was not written to.

The software doesn't have to sync the bitmap in the image file with its
representation in RAM after each write or metadata change. Flag 'in_use'
should be set while the bitmap is not synced.

In the image file the 'enabled' state is reflected by the 'auto' flag. If this
flag is set, the software must consider the bitmap as 'enabled' and start
tracking virtual disk changes to this bitmap from the first write to the
virtual disk. If this flag is not set then the bitmap is disabled.

## Data Encryption

When an encryption method is requested in the header, the image payload
data must be encrypted/decrypted on every write/read. The image headers
and metadata are never encrypted.

The algorithms used for encryption vary depending on the method

 - AES:

   The AES cipher, in CBC mode, with 256 bit keys.

   Initialization vectors generated using plain64 method, with
   the virtual disk sector as the input tweak.

   This format is no longer supported in QEMU system emulators, due
   to a number of design flaws affecting its security. It is only
   supported in the command line tools for the sake of back compatibility
   and data liberation.

 - LUKS:

   The algorithms are specified in the LUKS header.

   Initialization vectors generated using the method specified
   in the LUKS header, with the physical disk sector as the
   input tweak.

## References
https://people.gnome.org/~markmc/qcow-image-format.html

https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt

https://juliofaracco.wordpress.com/2015/02/19/an-introduction-to-qcow2-image-format/

https://mirage.github.io/ocaml-qcow/Qcow.Header.html

https://wiki.qemu.org/Features/Qcow3
