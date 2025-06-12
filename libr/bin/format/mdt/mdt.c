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

// Helper functions implementation
R_API RBinMdtPart *r_bin_mdt_part_new(const char *name, ut32 p_flags) {
	RBinMdtPart *part = R_NEW0(RBinMdtPart);
	if (!part) {
		return NULL;
	}
	part->name = name ? strdup(name) : NULL;
	part->relocatable = p_flags & QCOM_MDT_RELOCATABLE;
	part->is_layout = (p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT;
	part->pflags = p_flags;
	part->format = R_BIN_MDT_PART_UNIDENTIFIED;
	return part;
}

R_API void r_bin_mdt_part_free(RBinMdtPart *part) {
	if (!part) {
		return;
	}
	if (part->buf) {
		r_buf_free(part->buf);
	}
	if (part->mbn) {
		free(part->mbn);
	}
	free(part->name);
	free(part);
}

R_API RBinMdtObj *r_bin_mdt_obj_new(void) {
	RBinMdtObj *obj = R_NEW0(RBinMdtObj);
	if (!obj) {
		return NULL;
	}
	obj->parts = r_list_newf((RListFree)r_bin_mdt_part_free);
	obj->sections = r_list_newf((RListFree)r_bin_section_free);
	obj->maps = r_list_newf(free);
	return obj;
}

R_API void r_bin_mdt_obj_free(RBinMdtObj *obj) {
	if (!obj) {
		return;
	}
	r_list_free(obj->parts);
	r_list_free(obj->sections);
	r_list_free(obj->maps);
	free(obj->name);
	free(obj);
}

// Check if buffer is MDT format
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
	ut16 machine = r_read_le16(ehdr + 18);
	
	// Must be Hexagon architecture
	if (machine != 0xa4) {
		return false;
	}
	
	if (phnum == 0 || phoff == 0) {
		return false;
	}
	
	// Check for MDT-specific segment patterns
	bool has_layout_segment = false;
	bool has_relocatable_segments = false;
	bool has_signature_segment = false;
	
	for (int i = 0; i < phnum && i < 10; i++) {
		ut8 phdr[32];
		if (r_buf_read_at(b, phoff + i * 32, phdr, 32) != 32) {
			continue;
		}
		
		ut32 p_type = r_read_le32(phdr + 0);
		ut32 p_flags = r_read_le32(phdr + 24);
		
		if (p_type != 1) { // PT_LOAD
			continue;
		}
		
		// Check for MDT-specific Qualcomm flags
		if ((p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT) {
			has_layout_segment = true;
		}
		if ((p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
			has_signature_segment = true;
		}
		if (p_flags & QCOM_MDT_RELOCATABLE) {
			has_relocatable_segments = true;
		}
	}
	
	// MDT files should have both layout segment and relocatable segments
	// This distinguishes them from regular ELF files
	return has_layout_segment && (has_relocatable_segments || has_signature_segment);
}

// Create basic sections from MDT structure
static void create_mdt_sections(RBinMdtObj *mdt) {
	if (!mdt) {
		return;
	}
	
	// Create a basic .text section
	RBinSection *section = R_NEW0(RBinSection);
	if (section) {
		section->name = strdup("mdt_firmware");
		section->vaddr = 0x87400000;
		section->paddr = 0;
		section->size = 0x100000;
		section->vsize = 0x100000;
		section->perm = R_PERM_RX;
		section->add = true;
		r_list_append(mdt->sections, section);
	}
}

// Create basic memory maps
static void create_mdt_maps(RBinMdtObj *mdt) {
	if (!mdt) {
		return;
	}
	
	// Create basic memory map
	RBinMap *map = R_NEW0(RBinMap);
	if (map) {
		map->addr = 0x87400000;
		map->offset = 0;
		map->size = 0x100000;
		map->perms = R_PERM_RX;
		map->file = strdup("mdt_firmware");
		r_list_append(mdt->maps, map);
	}
}

// Get base path without .mdt extension  
static char *get_mdt_base_path(const char *filename) {
	if (!filename) {
		return NULL;
	}
	
	char *base = strdup(filename);
	if (!base) {
		return NULL;
	}
	
	char *dot = strrchr(base, '.');
	if (dot && !strcmp(dot, ".mdt")) {
		*dot = '\0';
	}
	
	return base;
}

// Parse ELF program headers to identify MDT segments
static bool parse_mdt_segments(RBinMdtObj *mdt, RBuffer *buf) {
	ut8 ehdr[52];
	if (r_buf_read_at(buf, 0, ehdr, 52) != 52) {
		return false;
	}
	
	ut32 phoff = r_read_le32(ehdr + 28);
	ut16 phnum = r_read_le16(ehdr + 44);
	ut16 phentsize = r_read_le16(ehdr + 42);
	
	if (phentsize != 32) { // ELF32 program header size
		return false;
	}
	
	for (int i = 0; i < phnum; i++) {
		ut8 phdr[32];
		if (r_buf_read_at(buf, phoff + i * 32, phdr, 32) != 32) {
			continue;
		}
		
		ut32 p_type = r_read_le32(phdr + 0);
		ut32 p_flags = r_read_le32(phdr + 24);
		ut32 p_vaddr = r_read_le32(phdr + 8);
		
		if (p_type != 1) { // PT_LOAD
			continue;
		}
		
		char *part_name = r_str_newf("%s.b%02d", mdt->name, i);
		if (!part_name) {
			continue;
		}
		
		RBinMdtPart *part = r_bin_mdt_part_new(part_name, p_flags);
		if (part) {
			part->paddr = p_vaddr;
			
			// Determine format based on flags
			if ((p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
				part->format = R_BIN_MDT_PART_MBN;
			} else if ((p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT) {
				part->format = R_BIN_MDT_PART_ELF;
			}
			
			r_list_append(mdt->parts, part);
		}
		free(part_name);
	}
	
	return true;
}

// Main load function
R_API bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb) {
	R_RETURN_VAL_IF_FAIL(obj && buf, false);
	
	if (!r_bin_mdt_check_buffer(buf)) {
		return false;
	}
	
	RBinMdtObj *mdt = r_bin_mdt_obj_new();
	if (!mdt) {
		return false;
	}

	mdt->name = get_mdt_base_path(bf->file);
	if (!mdt->name) {
		mdt->name = strdup("mdt_firmware");
	}
	
	// Parse MDT structure from ELF headers
	if (!parse_mdt_segments(mdt, buf)) {
		r_bin_mdt_obj_free(mdt);
		return false;
	}
	
	// Create basic sections and maps
	create_mdt_sections(mdt);
	create_mdt_maps(mdt);
	
	obj->bin_obj = mdt;
	return true;
}

R_API void r_bin_mdt_destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->bo && bf->bo->bin_obj);
	r_bin_mdt_obj_free(bf->bo->bin_obj);
}

R_API RList *r_bin_mdt_get_maps(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	
	RList *maps = r_list_newf(free);
	if (!maps) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMap *map;
	r_list_foreach(mdt->maps, iter, map) {
		RBinMap *clone = R_NEW0(RBinMap);
		if (clone) {
			memcpy(clone, map, sizeof(RBinMap));
			clone->file = map->file ? strdup(map->file) : NULL;
			r_list_append(maps, clone);
		}
	}
	
	return maps;
}

R_API RList *r_bin_mdt_get_entry_points(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	
	RList *entries = r_list_newf(free);
	if (!entries) {
		return NULL;
	}
	
	RBinAddr *entry = R_NEW0(RBinAddr);
	if (entry) {
		entry->paddr = 0;
		entry->vaddr = 0x87400000;  // Typical firmware entry
		entry->type = R_BIN_ENTRY_TYPE_INIT;
		entry->bits = 32;
		r_list_append(entries, entry);
	}
	
	return entries;
}

R_API RList *r_bin_mdt_symbols(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	
	// Return empty symbols list for now
	return r_list_newf((RListFree)r_bin_symbol_free);
}

R_API RList *r_bin_mdt_sections(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	
	RList *sections = r_list_newf((RListFree)r_bin_section_free);
	if (!sections) {
		return NULL;
	}
	
	RListIter *iter;
	RBinSection *sec;
	r_list_foreach(mdt->sections, iter, sec) {
		RBinSection *clone = r_bin_section_clone(sec);
		if (clone) {
			r_list_append(sections, clone);
		}
	}
	
	return sections;
}

R_API RList *r_bin_mdt_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	
	// Return empty relocs list for now
	return r_list_newf(free);
}

R_API void r_bin_mdt_print_header(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->rbin && bf->rbin->cb_printf);
	
	if (!bf->bo || !bf->bo->bin_obj) {
		bf->rbin->cb_printf("ERROR: Missing bin header fields\n");
		return;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	PrintfCallback cb = bf->rbin->cb_printf;
	
	cb("==== MDT Firmware Header ====\n");
	cb("Name: %s\n", mdt->name ? mdt->name : "unknown");
	cb("Parts: %d\n", r_list_length(mdt->parts));
	
	size_t i = 0;
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		char bits[65] = { 0 };
		r_str_bits64(bits, part->pflags);
		
		cb("==== MDT Segment %zu ====\n", i);
		cb("     priv_p_flags: 0b%s:", bits);
		
		if (part->is_layout) {
			cb(" layout");
		}
		if (part->relocatable) {
			cb(" reloc");
		}
		
		switch (part->format) {
		default:
		case R_BIN_MDT_PART_UNIDENTIFIED:
			cb(" | Unidentified\n");
			break;
		case R_BIN_MDT_PART_ELF:
			cb(" | ELF\n");
			break;
		case R_BIN_MDT_PART_MBN:
			cb(" | MBN signature segment\n");
			break;
		}
		i++;
	}
}