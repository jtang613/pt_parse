/******************************************************************************
Partition Table Parser

MIT License

Copyright (c) 2019 Jason Tang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/
#define _FILE_OFFSET_BITS 64
#define __USE_LARGEFILE64
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

/******************************************************************************
Logging macros
******************************************************************************/
#ifndef LOG
#define LOG 0
#endif

#if 1
#define _LOG_(severity, desc, fmt, ...) \
	do { \
		if (LOG > severity) { \
			time_t timer; \
			char buffer[26]; \
			struct tm* tm_info; \
			\
			time(&timer); \
			tm_info = localtime(&timer); \
			\
			strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info); \
			fprintf (stderr, "%s - %s: %s:%s():%d | " fmt, buffer, \
			desc, __FILE__, __func__, __LINE__  ,## __VA_ARGS__); \
		} \
	} while(0)

#define LOG_ERROR(fmt, ...) _LOG_(0, "ERROR", fmt,## __VA_ARGS__) 
#define LOG_WARN(fmt, ...)  _LOG_(1, "WARN", fmt,## __VA_ARGS__) 
#define LOG_INFO(fmt, ...)  _LOG_(2, "INFO", fmt,## __VA_ARGS__) 
#define LOG_DEBUG(fmt, ...) _LOG_(3, "DEBUG", fmt,## __VA_ARGS__) 
#else
#define _LOG_(severity, desc, fmt, ...) \
	do { \
		if (LOG > severity) { \
			time_t timer; \
			char buffer[26]; \
			struct tm* tm_info; \
			\
			time(&timer); \
			tm_info = localtime(&timer); \
			\
			strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info); \
			fprintf (stderr, "%s - %s: %s:%s():%d | " fmt, buffer, \
			desc, __FILE__, __func__, __LINE__  __VA_OPT__(,) __VA_ARGS__); \
		} \
	} while(0)

#define LOG_ERROR(fmt, ...) _LOG_(0, "ERROR", fmt, __VA_ARGS__) 
#define LOG_WARN(fmt, ...)  _LOG_(1, "WARN", fmt, __VA_ARGS__) 
#define LOG_INFO(fmt, ...)  _LOG_(2, "INFO", fmt, __VA_ARGS__) 
#define LOG_DEBUG(fmt, ...) _LOG_(3, "DEBUG", fmt, __VA_ARGS__) 
#endif

/******************************************************************************
Lookup tables
******************************************************************************/
char fs_type_names[][32][32] = {
	{"??????", "Unknown"},
	{"-FVE-FS-", "Bitlocker"},
	{"NTFS", "NTFS"},
	{"FAT", "FAT"},
	{"LUKS", "LUKS"}
};

uint8_t fs_lookup(char *fs_magic)
{
	for (int i=0; i<5; i++)
	{
		for (int j=0; j<16; j++)
		{
			if (strncasecmp(fs_type_names[i][0], 
						fs_magic+j, 
						strnlen(fs_type_names[i][0], 32)) == 0) 
				return i;
		}
	}
	return 0;
}

char mbr_type_names[][32] = {
	"Empty",	"FAT12",	"XENIX root",	"XENIX usr",	"FAT16 <32M",
	"Extended",	"FAT16",	"HPFS/NTFS/exFAT",	"AIX",	"AIX bootable",
	"OS/2 Boot Manag",	"W95 FAT32",	"W95 FAT32 (LBA)",	"Unknown",
	"W95 FAT16 (LBA)",	"W95 Ext'd (LBA)",	"OPUS",	"Hidden FAT12",
	"Compaq diagnost",	"Unknown",	"Hidden FAT16 <32M",	"Unknown",
	"Hidden FAT16",	"Hidden HPFS/NTFS",	"AST SmartSleep",	"Unknown",
	"Unknown",	"Hidden W95 FAT32",	"Hidden W95 FAT32",	"Unknown",
	"Hidden W95 FAT16",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"NEC DOS",	"Unknown",
	"Unknown",	"Hidden NTFS Win",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Plan 9",
	"Unknown",	"Unknown",	"PartitionMagic",	"Unknown",
	"Unknown",	"Unknown",	"Venix 80286",	"PPC PReP Boot",
	"SFS",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"QNX4.x",
	"QNX4.x 2nd part",	"QNX4.x 3rd part",	"OnTrack DM",	"OnTrack DM6 Aux",
	"CP/M",	"OnTrack DM6 Aux",	"OnTrackDM6",	"EZ-Drive",
	"Golden Bow",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Priam Edisk",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"SpeedStor",
	"Unknown",	"GNU HURD or Sys",	"Novell Netware",	"Novell Netware",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"DiskSecure Mult",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"PC/IX",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Old Minix",	"Minix / old Linux",
	"Linux swap / So",	"Linux",	"OS/2 hidden or",	"Linux extended",
	"NTFS volume set",	"NTFS volume set",	"Linux plaintext",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Linux LVM",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Amoeba",	"Amoeba BBT",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"BSD/OS",	"IBM Thinkpad hi",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"FreeBSD",
	"OpenBSD",	"NeXTSTEP",	"Darwin UFS",	"NetBSD",
	"Unknown",	"Darwin boot",	"Unknown",	"Unknown",
	"Unknown",	"HFS / HFS+",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"BSDI fs",	"BSDI swap",	"Unknown",
	"Unknown",	"Boot Wizard hid",	"Acronis FAT32 LBA",	"Unknown",
	"Solaris boot",	"Solaris",	"Unknown",	"DRDOS/sec (FAT-12)",
	"Unknown",	"Unknown",	"DRDOS/sec (FAT-16)",	"Unknown",
	"DRDOS/sec (FAT-32)",	"Syrinx",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Non-FS data",	"CP/M / CTOS / .",	"Unknown",	"Unknown",
	"Dell Utility",	"BootIt",	"Unknown",	"DOS access",
	"Unknown",	"DOS R/O",	"SpeedStor",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Rufus alignment",	"BeOS fs",	"Unknown",	"Unknown",
	"GPT",	"EFI (FAT-12/16/32)",	"Linux/PA-RISC boot",	"SpeedStor",
	"DOS secondary",	"Unknown",	"SpeedStor",	"Unknown",
	"Unknown",	"Unknown",	"Unknown",	"Unknown",
	"Unknown",	"VMware VMFS",	"VMware VMKCORE",	"Linux raid auto",
	"LANstep",	"BBT"
};

char gpt_type_names[][32][40] = { 
	{"00000000-0000-0000-0000-000000000000", "Empty"},
	{"c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "EFI System"},
	{"024dee41-33e7-11d3-9d69-0008c781f39f", "MBR partition scheme"},
	{"d3bfe2de-3daf-11df-ba40-e3a556d89593", "Intel Fast Flash"},
	{"21686148-6449-6e6f-744e-656564454649", "BIOS boot"},
	{"f4019732-066e-4e12-8273-346c5641494f", "Sony boot partition"},
	{"bfbfafe7-a34f-448a-9a5b-6213eb736c22", "Lenovo boot partition"},
	{"9e1a2d38-c612-4316-aa26-8b49521e5a8b", "PowerPC PReP boot"},
	{"7412f7d5-a156-4b13-81dc-867174929325", "ONIE boot"},
	{"d4e6e2cd-4469-46f3-b5cb-1bff57afc149", "ONIE config"},
	{"e3c9e316-0b5c-4db8-817d-f92df00215ae", "Microsoft reserved"},
	{"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "Microsoft basic data"},
	{"5808c8aa-7e8f-42e0-85d2-e1e90434cfb3", "Microsoft LDM metadata"},
	{"af9b60a0-1431-4f62-bc68-3311714a69ad", "Microsoft LDM data"},
	{"de94bba4-06d1-4d40-a16a-bfd50179d6ac", "Windows recovery environment"},
	{"37affc90-ef7d-4e96-91c3-2d7ae055b174", "IBM General Parallel Fs"},
	{"e75caf8f-f680-4cee-afa3-b001e56efc2d", "Microsoft Storage Spaces"},
	{"75894c1e-3aeb-11d3-b7c1-7b03a0000000", "HP-UX data"},
	{"e2a1e728-32e3-11d6-a682-7b03a0000000", "HP-UX service"},
	{"0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "Linux swap"},
	{"0fc63daf-8483-4772-8e79-3d69d8477de4", "Linux filesystem"},
	{"3b8f8425-20e0-4f3b-907f-1a25a76f98e8", "Linux server data"},
	{"44479540-f297-41b2-9af7-d131d5f0458a", "Linux root (x86)"},
	{"69dad710-2ce4-4e3c-b16c-21a1d49abed3", "Linux root (ARM)"},
	{"4f68bce3-e8cd-4db1-96e7-fbcaf984b709", "Linux root (x86-64)"},
	{"b921b045-1df0-41c3-af44-4c6f280d3fae", "Linux root (ARM-64)"},
	{"993d8d3d-f80e-4225-855a-9daf8ed7ea97", "Linux root  (IA-64)"},
	{"8da63339-0007-60c0-c436-083ac8230908", "Linux reserved"},
	{"933ac7e1-2eb4-4f13-b844-0e14e2aef915", "Linux home"},
	{"a19d880f-05fc-4d3b-a006-743f0f84911e", "Linux RAID"},
	{"bc13c2ff-59e6-4262-a352-b275fd6f7172", "Linux extended boot"},
	{"e6d6d379-f507-44c2-a23c-238f2a3df928", "Linux LVM"},
	{"516e7cb4-6ecf-11d6-8ff8-00022d09712b", "FreeBSD data"},
	{"83bd6b9d-7f41-11dc-be0b-001560b84f0f", "FreeBSD boot"},
	{"516e7cb5-6ecf-11d6-8ff8-00022d09712b", "FreeBSD swap"},
	{"516e7cb6-6ecf-11d6-8ff8-00022d09712b", "FreeBSD UFS"},
	{"516e7cba-6ecf-11d6-8ff8-00022d09712b", "FreeBSD ZFS"},
	{"516e7cb8-6ecf-11d6-8ff8-00022d09712b", "FreeBSD Vinum"},
	{"48465300-0000-11aa-aa11-00306543ecac", "Apple HFS/HFS+"},
	{"55465300-0000-11aa-aa11-00306543ecac", "Apple UFS"},
	{"52414944-0000-11aa-aa11-00306543ecac", "Apple RAID"},
	{"52414944-5f4f-11aa-aa11-00306543ecac", "Apple RAID offline"},
	{"426f6f74-0000-11aa-aa11-00306543ecac", "Apple boot"},
	{"4c616265-6c00-11aa-aa11-00306543ecac", "Apple label"},
	{"5265636f-7665-11aa-aa11-00306543ecac", "Apple TV recovery"},
	{"53746f72-6167-11aa-aa11-00306543ecac", "Apple Core storage"},
	{"6a82cb45-1dd2-11b2-99a6-080020736631", "Solaris boot"},
	{"6a85cf4d-1dd2-11b2-99a6-080020736631", "Solaris root"},
	{"6a898cc3-1dd2-11b2-99a6-080020736631", "Solaris /usr & Apple ZFS"},
	{"6a87c46f-1dd2-11b2-99a6-080020736631", "Solaris swap"},
	{"6a8b642b-1dd2-11b2-99a6-080020736631", "Solaris backup"},
	{"6a8ef2e9-1dd2-11b2-99a6-080020736631", "Solaris /var"},
	{"6a90ba39-1dd2-11b2-99a6-080020736631", "Solaris /home"},
	{"6a9283a5-1dd2-11b2-99a6-080020736631", "Solaris alternate sector"},
	{"6a945a3b-1dd2-11b2-99a6-080020736631", "Solaris reserved 1"},
	{"6a9630d1-1dd2-11b2-99a6-080020736631", "Solaris reserved 2"},
	{"6a980767-1dd2-11b2-99a6-080020736631", "Solaris reserved 3"},
	{"6a96237f-1dd2-11b2-99a6-080020736631", "Solaris reserved 4"},
	{"6a8d2ac7-1dd2-11b2-99a6-080020736631", "Solaris reserved 5"},
	{"49f48d32-b10e-11dc-b99b-0019d1879648", "NetBSD swap"},
	{"49f48d5a-b10e-11dc-b99b-0019d1879648", "NetBSD FFS"},
	{"49f48d82-b10e-11dc-b99b-0019d1879648", "NetBSD LFS"},
	{"2db519c4-b10e-11dc-b99b-0019d1879648", "NetBSD concatenated"},
	{"2db519ec-b10e-11dc-b99b-0019d1879648", "NetBSD encrypted"},
	{"49f48daa-b10e-11dc-b99b-0019d1879648", "NetBSD RAID"},
	{"fe3a2a5d-4f32-41a7-b725-accc3285a309", "ChromeOS kernel"},
	{"3cb8e202-3b7e-47dd-8a3c-7ff2a13cfcec", "ChromeOS root fs"},
	{"2e0a753d-9e48-43b0-8337-b15192cb1b5e", "ChromeOS reserved"},
	{"85d5e45a-237c-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD data"},
	{"85d5e45e-237c-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD boot"},
	{"85d5e45b-237c-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD swap"},
	{"0394ef8b-237e-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD UFS"},
	{"85d5e45d-237c-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD ZFS"},
	{"85d5e45c-237c-11e1-b4b3-e89a8f7fc3a7", "MidnightBSD Vinum"},
	{"45b0969e-9b03-4f30-b4c6-b4b80ceff106", "Ceph Journal"},
	{"45b0969e-9b03-4f30-b4c6-5ec00ceff106", "Ceph Encrypted Journal"},
	{"4fbd7e29-9d25-41b8-afd0-062c0ceff05d", "Ceph OSD"},
	{"4fbd7e29-9d25-41b8-afd0-5ec00ceff05d", "Ceph crypt OSD"},
	{"89c57f98-2fe5-4dc0-89c1-f3ad0ceff2be", "Ceph disk in creation"},
	{"89c57f98-2fe5-4dc0-89c1-5ec00ceff2be", "Ceph crypt disk in creation"},
	{"aa31e02a-400f-11db-9590-000c2911d1b8", "VMware VMFS"},
	{"9d275380-40ad-11db-bf97-000c2911d1b8", "VMware Diagnostic"},
	{"381cfccc-7288-11e0-92ee-000c2911d0b2", "VMware Virtual SAN"},
	{"77719a0c-a4a0-11e3-a47e-000c29745a24", "VMware Virsto"},
	{"9198effc-31c0-11db-8f78-000c2911d1b8", "VMware Reserved"},
	{"824cc7a0-36a8-11e3-890a-952519ad3f61", "OpenBSD data"},
	{"cef5a9ad-73bc-4601-89f3-cdeeeee321a1", "QNX6 file system"},
	{"c91818f9-8025-47af-89d2-f030d7000c2c", "Plan 9 partition"},
	{"5b193300-fc78-40cd-8002-e86c45580b47", "HiFive Unleashed FSBL"},
	{"2e54b353-1271-4842-806f-e436d6af6985", "HiFive Unleashed BBL"}
};

uint8_t gpt_type_lookup(char *type_guid)
{
	for (int i=0; i<90; i++)
	{
		if (strncmp(gpt_type_names[i][0], type_guid, 40) == 0) return i;
	}
	return 0;
}

/******************************************************************************
Disk partition structures
******************************************************************************/
#pragma pack(push, 1)
typedef struct _mbr_entry
{
	uint8_t status;
	struct
	{
		uint8_t head;
		uint8_t sector;
		uint8_t cylinder;
	} first_sector;
	uint8_t type;
	struct
	{
		uint8_t head;
		uint8_t sector;
		uint8_t cylinder;
	} last_sector;
	uint32_t lba;
	uint32_t sectors;
} mbr_entry;

typedef struct _mbr_table 
{
	uint8_t bootstrap1[218];
	uint16_t _z1;
	struct
	{
		uint8_t drive;
		uint8_t seconds;
		uint8_t minutes;
		uint8_t hours;
	} timestamp;
	uint8_t bootstrap2[216];
	uint32_t disk_sig;
	uint16_t _z2;
	mbr_entry part[4];
	union
	{
		uint8_t c[2];
		uint16_t s;
	} magic;
} mbr_table;

typedef struct _guid_t {
	uint32_t a;
	uint16_t b;
	uint16_t c;
	uint16_t d;
	uint8_t  e[6];
} guid_t;

typedef struct _gpt_table
{
	uint64_t sig;
	uint32_t rev;
	uint32_t header_size;
	uint32_t crc;
	uint32_t _z1;
	uint64_t cur_lba;
	uint64_t bak_lba;
	uint64_t first_lba;
	uint64_t last_lba;
	guid_t disk_guid;
	uint64_t part_lba;
	uint32_t part_count;
	uint32_t part_size;
	uint32_t part_crc;
	uint8_t  reserved[420];
} gpt_table;

typedef struct _gpt_entry
{
	guid_t type_guid;
	guid_t part_guid;
	uint64_t first_lba;
	uint64_t last_lba;
	uint64_t flags;
	uint8_t name[72];
} gpt_entry;
#pragma pack(pop)

/******************************************************************************
Normalized partition data
******************************************************************************/
typedef struct _partition
{
	uint64_t lba;
	uint64_t offset;
	uint64_t sectors;
	uint64_t size;
	char type[40];
	char filesystem[40];
} partition;

typedef struct _partition_table
{
	partition **entries;
	uint32_t size;
	char type[4];
} partition_table;

int pt_add(partition_table *pt, uint64_t lba, uint64_t sectors, char *type, char *filesystem)
{
	pt->entries = (partition**)realloc(pt->entries, sizeof(partition*) * (pt->size + 1));

	if (pt->entries == NULL)
	{
		LOG_ERROR("Failed to realloc entries list.\n");
		return 0;
	}
	pt->size += 1;
	
	pt->entries[pt->size-1] = (partition*)malloc(sizeof(partition));
	
	if (pt->entries[pt->size-1] == NULL)
	{
		LOG_ERROR("Failed to alloc partition entry.\n");
		return 0;
	}
	pt->entries[pt->size-1]->lba = lba;
	pt->entries[pt->size-1]->offset = lba*512;
	pt->entries[pt->size-1]->sectors = sectors;
	pt->entries[pt->size-1]->size = sectors*512;
	strncpy(pt->entries[pt->size-1]->type, type, 40);
	strncpy(pt->entries[pt->size-1]->filesystem, filesystem, 40);

	return pt->size;
}

void pt_sort(partition_table *pt)
{
	partition *temp = NULL;
	int min;

	for (int i=0; i<pt->size-1; i++)
	{
		min = i;
		for (int j=i+1; j<pt->size; j++)
		{
			if (pt->entries[j]->size > pt->entries[min]->size)
			{
				min = j;
			}
		}
		if (min != i)
		{
			temp = pt->entries[min];
			pt->entries[min] = pt->entries[i];
			pt->entries[i] = temp;
		}
	}
	return;
}

/******************************************************************************
Partition parsing
******************************************************************************/
int mbr_parse(FILE *fd, off_t offset, mbr_table **mbr, int id, partition_table *pt)
{
	size_t ret = 0;
	uint8_t buf[512] = {};
	char fs_magic[32] = {};
	uint8_t fs_index = 0;

	mbr[id] = (mbr_table*)malloc(sizeof(mbr_table));
	if (mbr[id] == NULL)
	{
		LOG_ERROR("Failed to malloc.\n");
		return 0;
	}
	
	fseek(fd, offset*512, SEEK_SET);
	ret = fread(mbr[id], sizeof(mbr_table), 1, fd);
	if (ret != 1)
	{
		LOG_ERROR("Failed to read MBR.\n");
		return 0;
	}

	if (mbr[id]->magic.s != 0xaa55)
	{
		LOG_ERROR("Not a DOS partition table.\n");
		return 0;
	}
	LOG_DEBUG("Found a DOS partition table.\n");

	for (int i=0; i<4; i++)
	{
		if (mbr[id]->part[i].type == 0) continue;

		fseek(fd, (mbr[id]->part[i].lba+offset)*512, SEEK_SET);
		ret = fread(fs_magic, 32, 1, fd);
		fs_index = fs_lookup(fs_magic);

		LOG_DEBUG("Partition - LBA: %lu  Sectors: %u  Type: %s  FS: %s\n",
			mbr[id]->part[i].lba+offset, 
			mbr[id]->part[i].sectors, 
			mbr_type_names[mbr[id]->part[i].type],
			fs_type_names[fs_index][1]);

		pt_add (pt, 
			mbr[id]->part[i].lba+offset, 
			mbr[id]->part[i].sectors, 
			mbr_type_names[mbr[id]->part[i].type],
			fs_type_names[fs_index][1]);

		if (mbr[id]->part[i].type == 5)
		{
			LOG_DEBUG("Parsing extended partition table at offset %u.\n", mbr[id]->part[i].lba);
			ret = mbr_parse(fd, mbr[id]->part[i].lba, mbr, 1, pt);

			if (ret == 0)
			{
				LOG_ERROR("Failed to parse extended partition table.\n");
				break;
			}
		}
		else if (mbr[id]->part[i].type == 0xee)
		{
			LOG_DEBUG("Found a GPT partition identifier.\n");
			return -1;
		}
		
	}

	strncpy(pt->type, "MBR", 4);
	return 1;
}

int gpt_parse(FILE *fd, off_t offset, gpt_table **_gpt, gpt_entry **_entries, partition_table *pt)
{
	size_t ret = 0;
	char type_guid[40] = {};
	char fs_magic[32] = {};
	uint8_t type_index = 0;
	uint8_t fs_index = 0;
	gpt_table *gpt = *_gpt;
	gpt_entry *entries = *_entries;

	gpt = (gpt_table*)malloc(sizeof(gpt_table));

	if (gpt == NULL)
	{
		LOG_ERROR("Failed to malloc.\n");
		return 0;
	}
	
	fseek(fd, offset*512, SEEK_SET);
	ret = fread(gpt, sizeof(gpt_table), 1, fd);

	if (ret != 1)
	{
		LOG_ERROR("Failed to read GPT.\n");
		return 0;
	}

	entries = (gpt_entry*)malloc(sizeof(gpt_entry) * gpt->part_count);
	fseek(fd, gpt->part_lba*512, SEEK_SET);
	ret = fread(entries, sizeof(gpt_entry), gpt->part_count, fd);

	if (ret != gpt->part_count)
	{
		LOG_ERROR("Failed to read GPT.\n");
		return 0;
	}

	LOG_DEBUG("GPT table has %d entries.\n", gpt->part_count);

	for (int i=0; i<gpt->part_count; i++)
	{
		
		gpt_entry entry = entries[i];
		snprintf(type_guid, 40, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x", 
				entries[i].type_guid.a,
				entries[i].type_guid.b,
				entries[i].type_guid.c,
				((entries[i].type_guid.d&0xff)<<8)+((entries[i].type_guid.d>>8)&0xff),
				entries[i].type_guid.e[0],
				entries[i].type_guid.e[1],
				entries[i].type_guid.e[2],
				entries[i].type_guid.e[3],
				entries[i].type_guid.e[4],
				entries[i].type_guid.e[5]);
		type_index = gpt_type_lookup(type_guid);
		LOG_DEBUG("GPT partition type: %s\n", type_guid);

		if (type_index == 0) continue;
		
		fseek(fd, entries[i].first_lba*512, SEEK_SET);
		ret = fread(fs_magic, 32, 1, fd);
		fs_index = fs_lookup(fs_magic);

		pt_add( pt, 
			entries[i].first_lba, 
			entries[i].last_lba - entries[i].first_lba + 1, 
			gpt_type_names[type_index][1],
			fs_type_names[fs_index][1]);
	}	
	
	LOG_DEBUG("Found a GPT partition table.\n");
	*_gpt = gpt;
	*_entries = entries;	
	strncpy(pt->type, "GPT", 4);
	return 1;
}

/******************************************************************************
Partition display
******************************************************************************/
void mbr_display(FILE *fd, mbr_table *mbr)
{

	char fs_magic[32] = {};
	uint8_t fs_index = 0;
	size_t ret = 0;

	printf("\nMBR Layout\n");
	printf(" #      Start    Sectors   Type  Name              FileSystem\n");
	for (int i=0; i<4; i++)
	{
		if (mbr->part[i].type == 0) continue;

		fseek(fd, mbr->part[i].lba*512, SEEK_SET);
		ret = fread(fs_magic, 32, 1, fd);
		fs_index = fs_lookup(fs_magic);

		printf("%2d %10u %10u   0x%02x  %-16s  %-16s\n", 
				i+1, 
				mbr->part[i].lba, 
				mbr->part[i].sectors, 
				mbr->part[i].type,
				mbr_type_names[mbr->part[i].type],
				fs_type_names[fs_index][1]);

	}

	return;
}

void gpt_display(FILE *fd, gpt_table *gpt, gpt_entry *parts)
{
	char type_guid[40] = {};
	char part_guid[40] = {};
	char fs_magic[32] = {};
	uint8_t type_index = 0;
	uint8_t fs_index = 0;
	size_t ret = 0;

	printf("\nGPT Layout\n");
	printf(" #      Start    Sectors   GUID                                  Type                 FileSystem\n");
	for (int i=0; i<gpt->part_count; i++)
	{
		snprintf(type_guid, 40, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x", 
				parts[i].type_guid.a,
				parts[i].type_guid.b,
				parts[i].type_guid.c,
				((parts[i].type_guid.d&0xff)<<8)+((parts[i].type_guid.d>>8)&0xff),
				parts[i].type_guid.e[0],
				parts[i].type_guid.e[1],
				parts[i].type_guid.e[2],
				parts[i].type_guid.e[3],
				parts[i].type_guid.e[4],
				parts[i].type_guid.e[5]);
		type_index = gpt_type_lookup(type_guid);

		if (type_index == 0) continue;

		fseek(fd, parts[i].first_lba*512, SEEK_SET);
		ret = fread(fs_magic, 32, 1, fd);
		fs_index = fs_lookup(fs_magic);

		snprintf(part_guid, 40, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x", 
				parts[i].part_guid.a,
				parts[i].part_guid.b,
				parts[i].part_guid.c,
				((parts[i].part_guid.d&0xff)<<8)+((parts[i].part_guid.d>>8)&0xff),
				parts[i].part_guid.e[0],
				parts[i].part_guid.e[1],
				parts[i].part_guid.e[2],
				parts[i].part_guid.e[3],
				parts[i].part_guid.e[4],
				parts[i].part_guid.e[5]);

		printf("%2d %10lu %10lu   %s  %-20s %-20s\n", 
				i+1, 
				parts[i].first_lba, 
				parts[i].last_lba - parts[i].first_lba + 1, 
				part_guid,
				gpt_type_names[type_index][1],
				fs_type_names[fs_index][1]);
	}

	return;
}

void pt_display(partition_table *pt, uint8_t verbose)
{
	if(verbose)
	{
		printf("\nGeneralized Layout\n");
		printf(" #            Offset              Size  Type                  FileSystem\n");
	}
	for (int i=0; i<pt->size; i++)
	{
		if (verbose)
		{
		printf("%2d  %16lu  %16lu  %-20s  %-20s\n",
				i+1,
				pt->entries[i]->offset,
				pt->entries[i]->size,
				pt->entries[i]->type,
				pt->entries[i]->filesystem);
		}
		else //if (strncmp("NTFS", pt->entries[i]->filesystem, 40) == 0)
		{
			printf("%lu,%lu,%s,%s\n",
					pt->entries[i]->offset,
					pt->entries[i]->size,
					pt->entries[i]->type,
					pt->entries[i]->filesystem);
			//break;
		}
	}
	return;
}

/******************************************************************************
******************************************************************************/
int main(int argc, char *argv[])
{
	FILE *in_file = NULL;
	int ret = 0;
	gpt_table *gpt = NULL;
	gpt_entry *gpt_entries = NULL;
	mbr_table *mbr[2] = {};
	partition_table pt = {};
	uint8_t verbose = 0;

	LOG_DEBUG("Modern MBR size: %ld\n", sizeof(mbr_table));

	if (argc == 3 && strncmp("-v", argv[1], 2) == 0)
	{
		printf("\nPartition Table Parser\n");
		printf("======================\n");
		verbose = 1;
	}
	else if (argc != 2)
	{
		printf("Usage: %s <IMG>\n", argv[0]);
		exit(1);
	}

	in_file = fopen(argv[argc-1], "r");
	if (in_file == NULL)
	{
		LOG_ERROR("Cannot open: %s\n", argv[1]);
		exit(1);
	}

	ret = mbr_parse(in_file, 0, mbr, 0, &pt);
	if (verbose) mbr_display(in_file, mbr[0]);
	LOG_DEBUG("mbr_parse returned: %d\n", ret);

	if (ret < 0)
	{
		gpt_parse(in_file, 1, &gpt, &gpt_entries, &pt);
		if (verbose) gpt_display(in_file, gpt, gpt_entries);
	}
	pt_sort(&pt);
	pt_display(&pt, verbose);

	if (mbr[0] != NULL) free(mbr[0]);
	if (mbr[1] != NULL) free(mbr[1]);
	if (gpt != NULL) free(gpt);
	if (gpt_entries != NULL) free(gpt_entries);
	for (int i=0; i<pt.size; i++)
	{
		if (pt.entries[i] != NULL) free(pt.entries[i]);
	}
	fclose(in_file);
	return 0;
}
