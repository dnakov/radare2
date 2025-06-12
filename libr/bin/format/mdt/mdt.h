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

typedef enum {
	R_BIN_MDT_PART_UNIDENTIFIED = 0,
	R_BIN_MDT_PART_ELF,
	R_BIN_MDT_PART_MBN,
} RBinMdtPartFormat;

// MBN header structure
typedef struct sbl_header {
	ut32 load_index;
	ut32 version;    // (flash_partition_version) 3 = nand
	ut32 paddr;      // This + 40 is the start of the code in the file
	ut32 vaddr;	 // Where it's loaded in memory
	ut32 psize;      // code_size + signature_size + cert_chain_size
	ut32 code_pa;    // Only what's loaded to memory
	ut32 sign_va;
	ut32 sign_sz;
	ut32 cert_va;    // Max of 3 certs?
	ut32 cert_sz;
} SblHeader;

// Simple MDT part structure
typedef struct r_bin_mdt_part_t {
	char *name;
	bool relocatable;
	bool is_layout;
	ut64 paddr;
	ut32 pflags;
	RBinMdtPartFormat format;
	RBuffer *buf;
	SblHeader *mbn;
} RBinMdtPart;

// Main MDT object
typedef struct r_bin_mdt_obj_t {
	char *name;
	RList *parts;  // List of RBinMdtPart
	RList *sections;   // Aggregated sections
	RList *maps;       // Memory maps
} RBinMdtObj;

// Core API functions
R_API bool r_bin_mdt_check_buffer(RBuffer *b);
R_API bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb);
R_API void r_bin_mdt_destroy(RBinFile *bf);
R_API RList *r_bin_mdt_get_maps(RBinFile *bf);
R_API RList *r_bin_mdt_get_entry_points(RBinFile *bf);
R_API RList *r_bin_mdt_symbols(RBinFile *bf);
R_API RList *r_bin_mdt_sections(RBinFile *bf);
R_API RList *r_bin_mdt_relocs(RBinFile *bf);
R_API void r_bin_mdt_print_header(RBinFile *bf);

// Helper functions
R_API RBinMdtPart *r_bin_mdt_part_new(const char *name, ut32 p_flags);
R_API void r_bin_mdt_part_free(RBinMdtPart *part);
R_API RBinMdtObj *r_bin_mdt_obj_new(void);
R_API void r_bin_mdt_obj_free(RBinMdtObj *obj);

#endif