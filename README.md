# pt_parse

A simple disk image partition table parser that supports both MBR and GPT types. Output can be both verbose and CSV machine readable (default) - useful for pulling disk image layouts into a processing pipeline.

## Sample Output
```
./pt_parse -v test_gpt.img

Partition Table Parser
======================

MBR Layout
 #      Start    Sectors   Type  Name              FileSystem
 1          1      99999   0xee  GPT               Unknown         

GPT Layout
 #      Start    Sectors   GUID                                  Type                 FileSystem
 1       2048      20480   40382efd-557d-2240-82cd-1da292eebdfb  Microsoft basic data Unknown             
 2      22528      77439   572e133e-8db4-3b46-b518-d69b2162970f  Microsoft reserved   Unknown             

Generalized Layout
 #            Offset              Size  Type                  FileSystem
 1               512          51199488  GPT                   Unknown             
 2          11534336          39648768  Microsoft reserved    Unknown             
 3           1048576          10485760  Microsoft basic data  Unknown             
```
