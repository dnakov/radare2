// mdt.h
// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R_BIN_MDT_H
#define R_BIN_MDT_H

#include <r_bin.h>
#include <r_util.h>

// Qualcomm-specific p_flags in ELF segment headers
#define QCOM_MDT_TYPE_MASK      0x7000000
#define QCOM_MDT_TYPE_LAYOUT    0x0000000
#define QCOM_MDT_TYPE_SIGNATURE 0x2000000
#define QCOM_MDT_RELOCATABLE    0x10000000

// Missing in radare2 but used in original code
#define R_BIN_ELF_TINY_SIZE     52

typedef enum {
	R_BIN_MDT_PART_UNIDENTIFIED = 0,
	R_BIN_MDT_PART_ELF,
	R_BIN_MDT_PART_MBN,
	R_BIN_MDT_PART_COMPRESSED_Q6ZIP,
	R_BIN_MDT_PART_COMPRESSED_CLADE2,
	R_BIN_MDT_PART_COMPRESSED_ZLIB,
} RBinMdtPartFormat;

typedef struct r_bin_mdt_obj_t {
	char *name;
	void *header;  // ELF header
	RList *parts;
} RBinMdtObj;

// Function declarations
R_API bool r_bin_mdt_check_buffer(RBuffer *b);
R_API bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb);
R_API void r_bin_mdt_destroy(RBinFile *bf);
R_API RList *r_bin_mdt_virtual_files(RBinFile *bf);
R_API RList *r_bin_mdt_get_maps(RBinFile *bf);
R_API RList *r_bin_mdt_get_entry_points(RBinFile *bf);
R_API RList *r_bin_mdt_symbols(RBinFile *bf);
R_API RList *r_bin_mdt_sections(RBinFile *bf);
R_API RList *r_bin_mdt_relocs(RBinFile *bf);
R_API void r_bin_mdt_print_header(RBinFile *bf);

#endif