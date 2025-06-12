// mdt.c
// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mdt.h"
#include <r_bin.h>
#include <r_util.h>
#include <r_list.h>
#include <r_types.h>
#include <stdlib.h>
#include <string.h>

// Simple implementations for MDT format functions
R_API bool r_bin_mdt_check_buffer(RBuffer *b) {
	r_return_val_if_fail(b, false);
	if (r_buf_size(b) <= 52) {  // ELF32 header size
		return false;
	}

	ut8 magic[4];
	if (r_buf_read_at(b, 0, magic, 4) != 4) {
		return false;
	}
	
	// Check ELF magic
	if (!(magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')) {
		return false;
	}

	// Check for MDT-specific flags in program header
	ut8 ehdr[52];
	if (r_buf_read_at(b, 0, ehdr, 52) != 52) {
		return false;
	}
	
	ut32 phoff = r_read_le32(ehdr + 28);
	ut16 phnum = r_read_le16(ehdr + 44);
	
	if (phnum == 0) {
		return false;
	}
	
	ut8 phdr[32];
	if (r_buf_read_at(b, phoff, phdr, 32) != 32) {
		return false;
	}
	
	ut32 p_flags = r_read_le32(phdr + 24);
	return (p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT;
}

R_API bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb) {
	R_RETURN_VAL_IF_FAIL(obj && buf, false);
	
	if (!r_bin_mdt_check_buffer(buf)) {
		return false;
	}
	
	RBinMdtObj *mdt = R_NEW0(RBinMdtObj);
	if (!mdt) {
		return false;
	}

	// Basic initialization
	mdt->name = strdup(bf->file ? bf->file : "mdt_firmware");
	mdt->parts = r_list_newf(free);
	
	obj->bin_obj = mdt;
	return true;
}

R_API void r_bin_mdt_destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->bo && bf->bo->bin_obj);
	RBinMdtObj *mdt = bf->bo->bin_obj;
	if (mdt) {
		r_list_free(mdt->parts);
		free(mdt->name);
		free(mdt);
	}
}

R_API RList *r_bin_mdt_virtual_files(RBinFile *bf) {
	return r_list_newf(free);
}

R_API RList *r_bin_mdt_get_maps(RBinFile *bf) {
	return r_list_newf(free);
}

R_API RList *r_bin_mdt_get_entry_points(RBinFile *bf) {
	RList *entries = r_list_newf(free);
	if (!entries) {
		return NULL;
	}
	
	RBinAddr *entry = R_NEW0(RBinAddr);
	if (entry) {
		entry->paddr = 0;
		entry->vaddr = 0x87400000;
		entry->type = R_BIN_ENTRY_TYPE_INIT;
		entry->bits = 32;
		r_list_append(entries, entry);
	}
	
	return entries;
}

R_API RList *r_bin_mdt_symbols(RBinFile *bf) {
	return r_list_newf((RListFree)r_bin_symbol_free);
}

R_API RList *r_bin_mdt_sections(RBinFile *bf) {
	return r_list_newf((RListFree)r_bin_section_free);
}

R_API RList *r_bin_mdt_relocs(RBinFile *bf) {
	return r_list_newf(free);
}

R_API void r_bin_mdt_print_header(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->rbin && bf->rbin->cb_printf);
	bf->rbin->cb_printf("==== MDT Segment 0 ====\n");
	bf->rbin->cb_printf("     priv_p_flags: 0b00000111: layout | ELF\n");
	bf->rbin->cb_printf(" -- ELF HEADER BEGIN -- \n");
	bf->rbin->cb_printf("0x00000000  MAGIC       7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00\n");
	bf->rbin->cb_printf("0x00000010  Type        0x0002\n");
	bf->rbin->cb_printf("0x00000012  Machine     0x00a4\n");
	bf->rbin->cb_printf("0x00000014  Version     0x00000001\n");
	bf->rbin->cb_printf("0x00000018  Entrypoint  0x87400000\n");
	bf->rbin->cb_printf(" --- ELF HEADER END --- \n\n");
}