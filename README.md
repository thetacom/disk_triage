# *Disk-Triage*

Disk-Triage is a Python tool for dissecting and analyzing disk image files. This tool is designed to be a command line utility.

## Disk Formats

### Supported

- RAW (.raw / .img / .dd / .iso / .loop)
- QCOW (.qcow / .qcow2 / .qcow3)  [QCOW Guide](https://github.com/thetacom/disk-triage/blob/master/docs/QCOW_Structure_Guide.md)


### Planned
- CLOOP
- VHD
- VMDK
- VDI
- DMG
- WIM

# Usage

```bash
./disk-triage.py [Global Options] [COMMAND] [Command Options] FILENAME
```
### Example 1: Output basic disk image info to screen
```bash
./disk-triage.py info disk.qcow
```

### Example 2: Output all table entries including zeros to screen
```bash
./disk-triage.py -z tables -a test.qcow
```
### Example 3: Output first virtual data cluster to screen
```bash
./disk-triage.py data -S -n 5 test.qcow
```
### Example 4: Output two virtual data clusters starting at the provided address to screen
```bash

./disk-triage.py data -a 0x912c -n 2 test.qcow
```
### Example 5: Output first five virtual data sectors to screen
```bash

./disk-triage.py data -S -n 5 test.qcow
```
### Example 6: Output first five physical data clusters to screen
```bash

./disk-triage.py data -p -n 5 test.qcow
```
### Example 7: Output first virtual cluster as raw unformatted data
```bash

./disk-triage.py data -r test.qcow
```

## Option Tree

```bash
usage: disk-triage.py [-h] [--version] [-v VERBOSITY] [-j] [-z]
                      {info,map,snapshots,metadata,tables,data,check,do} ...
                      FILE

Perform various low level triage functions on the provided disk image file.

positional arguments:
  {info,map,snapshots,metadata,tables,data,check,do}
    info                Output metadata and all tables from the disk image
                        file.
    map                 Output a visual block depiction of the disk image
                        file.
    snapshots           Output a visual block depiction of the disk image
                        file.
    metadata            Output metadata (attributes/header/trailer) of disk image file.
    tables              Output file tables.
    data                Output cluster meta-data of disk image file.
    check               Perform consistency checks on disk image file.
    do                  Various command shortcuts for manipulating a disk
                        image file.
  FILE                  Filename of the disk image to be triaged.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v VERBOSITY, --verbosity VERBOSITY
  -j, --json            Output results in JSON format.
  -z, --zeros           Output all values including empty entries (Do not
                        suppress unused entries/clusters/blocks).

Exit status: 0 if OK, 1 if minor problems(e.g., ...), 2 if serious trouble
(e.g. invalid filename).
```

### Info

```bash
usage: disk-triage.py info [-h] [-a] [-d]

optional arguments:
  -h, --help      show this help message and exit
  -a, --all       Output additional information including disk image tables.
  -d, --detailed  Perform deep inspection of values and additional validations
                  addresses and data.
```

### Map
```bash
usage: disk-triage.py map [-h] [-d]

optional arguments:
  -h, --help      show this help message and exit
  -d, --detailed  Perform deep inspection of values and additional validations
                  addresses and data.
```

### Snapshots
```bash
usage: disk-triage.py snapshots [-h] [-d]

optional arguments:
  -h, --help      show this help message and exit
  -d, --detailed  Perform deep inspection of values and additional validations
                  addresses and data.
```

###  Metadata
```bash
usage: disk-triage.py metadata [-h] [-d]

optional arguments:
  -h, --help      show this help message and exit
  -d, --detailed  Perform deep inspection of values and additional validations
                  addresses and data.
```

### Tables
```bash
usage: disk-triage.py tables [-h] [-a] [-p] [-s] [-R] [-d] [-n]

optional arguments:
  -h, --help       show this help message and exit
  -a, --all        Output all tables.
  -p, --primary    Output primary allocation tables.
  -s, --secondary  Output secondary allocation tables.
  -R, --raw        Output array of raw entries from parsed table(s).
  -d, --detailed   Perform deep inspection of values and additional
                   validations addresses and data.
  -n, --nonzero    Include possible non-zero entries beyond those marked as allocated (Enumerates all entries up to virtual data boundary).
```

### Data

```bash
usage: disk-triage.py data [-h] [-a 0xFFFFFFFFFFFFFFFF] [-p] [-H] [-d]
                           [-n NUMBER_OF_CHUNKS | -A] [-B | -S] [-r | -0 | -m]

optional arguments:
  -h, --help            show this help message and exit
  -A 0xFFFFFFFFFFFFFFFF, --address 0xFFFFFFFFFFFFFFFF
                        Starting virtual address of output.
  -p, --physical_address
                        (Specify the provided address is physical not virtual.
  -H, --human-readable  Output decoded data.
  -d, --detailed        Perform deep inspection of values and additional
                        validations addresses and data.
  -n NUMBER_OF_CHUNKS, --number_of_chunks NUMBER_OF_CHUNKS
                        Number of data chunks to output.
  -a, --all             Output all data within disk image.
  -B, --bytes           Output data in byte sized chunks.
  -S, --sectors         Output data in sector sized chunks.
  -r, --raw             Only a single block of raw data.
  -0, --no-data         Only output cluster metadata and no actual data.
  -m, --no-metadata     Only output data and no cluster metadata.
```

### Check
```bash
usage: disk-triage.py check [-h] [-d] [-a] [-D] [-l]

optional arguments:
  -h, --help          show this help message and exit
  -d, --detailed      Perform deep inspection of values and additional
                      validations addresses and data.
  -a, --all           Perform all consistency checks on disk image file.
  -D, --dereferenced  Check for dereferenced clusters.
  -l, --leaks         Check for leaked clusters.
```

### Do (Not Yet Implemented)
```bash
usage: disk-triage.py do [-h] {mount,unmount,restore} ...

positional arguments:
  {mount,unmount,restore}
    mount               Attempt to mount disk image file.
    unmount             Attempt to unmount disk image file.
    restore             Restore an existing snapshot.

optional arguments:
  -h, --help            show this help message and exit
```
