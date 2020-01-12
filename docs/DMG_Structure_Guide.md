# DMG File Structure
# Trailer
```c
typedef struct {
        uint8_t     Signature[4];
        uint32_t Version;
        uint32_t HeaderSize;
        uint32_t Flags;                 
        uint64_t RunningDataForkOffset;
        uint64_t DataForkOffset;
        uint64_t DataForkLength;
        uint64_t RsrcForkOffset;     
        uint64_t RsrcForkLength;        
        uint32_t SegmentNumber;
        uint32_t SegmentCount;
        uuid_t   SegmentID;
        uint32_t DataChecksumType;
        uint32_t DataChecksumSize;
        uint32_t DataChecksum[32];
        uint64_t XMLOffset; 
        uint64_t XMLLength; 
        uint8_t  Reserved1[120];
        uint32_t ChecksumType;
        uint32_t ChecksumSize;
        uint32_t Checksum[32];
        uint32_t ImageVariant;
        uint64_t SectorCount;
        uint32_t reserved2;
        uint32_t reserved3;
        uint32_t reserved4;
 } __attribute__((__packed__)) UDIFResourceFile;
 ```

## Trailer Explained:

| Position(in Hex) | Length (in bytes) | Description |
|-|-|-|
|000 | 4 | Magic bytes ('koly'). |
|004 | 4 | File version (current is 4) |
|008 | 4 | The length of this header, in bytes. Should be 512. |
|00C | 4 | Flags. |
|010 | 8 | Unknown. |
|018 | 8 | Data fork offset (usually 0, beginning of file) |
|020 | 8 | Size of data fork (usually up to the XMLOffset, below) |
|028 | 8 | Resource fork offset, if any |
|030 | 8 | Resource fork length, if any |
|038 | 4 | Segment number. Usually 1, may be 0 |
|03C | 4 | Segment count. Usually 1, may be 0 |
|040 | 16 | 128-bit GUID identifier of segment |
|050 | 4 | Data fork checksum type |
|054 | 4 | Data fork checksum size |
|058 | 128 | Data fork checksum |
|0D8 | 8 | Offset of XML property list in DMG, from beginning |
|0E0 | 8 | Length of XML property list |
|0E8 | 120 | Reserved bytes |
|160 | 4 | Master checksum type |
|164 | 4 | Master checksum size |
|168 | 128 | Master checksum |
|1E8 | 4 | Unknown, commonly 1 |
|1EC | 8 | Size of DMG when expanded, in sectors |
|1F4 | 12 | Reserved bytes (zeroes) |
|-|-|-|

Note: All fields in the koly block (and, in fact, elsewhere in the DMG format) are in big endian ordering. This is to preserve compatibility with older generations of OS X, which were PPC-based. This requires DMG implementations to use macros such as be##_to_cpu (16, 32, and 64).

# References
    http://newosxbook.com/DMG.html
    https://en.wikipedia.org/wiki/Apple_Disk_Image
    https://en.wikipedia.org/wiki/Sparse_image
    https://github.com/torarnv/sparsebundlefs
    
# Other Tools
    http://www.dataforensics.org/view-dmg-file/
    http://vu1tur.eu.org/tools/