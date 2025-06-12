/* radare2 - LGPL - Copyright 2024 - User */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mdt.h"

#define MDT_SIGNATURE "QTI_IMAGE"

// Helper function to check if buffer contains valid MDT signature
static bool is_valid_mdt_signature(RBuffer *buf) {
	ut8 sig[8] = {0};
	int read = r_buf_read_at (buf, 0, sig, sizeof(sig));
	if (read != sizeof(sig)) {
		return false;
	}
	return !memcmp (sig, MDT_SIGNATURE, 8);
}

// Check if buffer is a valid MDT file
bool r_bin_mdt_check(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, false);
	ut64 size = r_buf_size (buf);
	if (size < sizeof(MdtImageHeader)) {
		return false;
	}
	return is_valid_mdt_signature (buf);
}

// Free MDT part
static void r_bin_mdt_part_free(RBinMdtPart *part) {
	if (!part) {
		return;
	}
	free (part->name);
	r_buf_free (part->buf);
	free (part);
}

// Free MDT object
void r_bin_mdt_free(RBinMdtObj *obj) {
	if (!obj) {
		return;
	}
	
	if (obj->parts) {
		for (ut32 i = 0; i < obj->nparts; i++) {
			r_bin_mdt_part_free (obj->parts[i]);
		}
		free (obj->parts);
	}
	
	r_list_free (obj->segments);
	r_list_free (obj->sections);
	r_list_free (obj->symbols);
	r_list_free (obj->imports);
	r_list_free (obj->libs);
	r_list_free (obj->relocs);
	r_list_free (obj->maps);
	r_list_free (obj->entries);
	
	free (obj->arch);
	free (obj->machine);
	free (obj->os);
	r_buf_free (obj->buf);
	free (obj);
}

// Parse ELF segments from buffer
static void parse_elf_segments(RBinMdtObj *obj, RBuffer *buf, ut64 offset) {
	// This is a simplified ELF parser - in reality would need full ELF parsing
	ut8 elf_header[64] = {0};
	if (r_buf_read_at (buf, offset, elf_header, sizeof(elf_header)) != sizeof(elf_header)) {
		return;
	}
	
	// Check ELF magic
	if (memcmp (elf_header, "\x7f" "ELF", 4) != 0) {
		return;
	}
	
	// Extract basic ELF info
	obj->bits = (elf_header[4] == 1) ? 32 : 64;
	obj->big_endian = (elf_header[5] == 2);
	
	// Set architecture based on ELF machine type
	ut16 machine = r_read_le16 (elf_header + 18);
	switch (machine) {
	case 0x28: // ARM
		obj->arch = strdup ("arm");
		break;
	case 0xB7: // AArch64
		obj->arch = strdup ("arm");
		obj->bits = 64;
		break;
	case 0x3E: // x86-64
		obj->arch = strdup ("x86");
		obj->bits = 64;
		break;
	default:
		obj->arch = strdup ("unknown");
		break;
	}
}

// Parse MDT parts from buffer
static bool parse_mdt_parts(RBinMdtObj *obj) {
	// MDT files typically contain multiple parts/segments
	// This is a simplified parser - real implementation would be more complex
	
	ut64 current_offset = sizeof(MdtImageHeader);
	ut32 part_count = 0;
	
	// Allocate parts array
	obj->parts = R_NEWS0 (RBinMdtPart*, MDT_MAX_PARTS);
	if (!obj->parts) {
		return false;
	}
	
	// Parse parts from the buffer
	while (current_offset < obj->size && part_count < MDT_MAX_PARTS) {
		ut8 part_header[32] = {0};
		if (r_buf_read_at (obj->buf, current_offset, part_header, sizeof(part_header)) != sizeof(part_header)) {
			break;
		}
		
		// Check for valid part signature/magic
		if (part_header[0] == 0 && part_header[1] == 0) {
			break; // End of parts
		}
		
		RBinMdtPart *part = R_NEW0 (RBinMdtPart);
		if (!part) {
			break;
		}
		
		// Parse part information
		ut32 part_size = r_read_le32 (part_header + 4);
		ut32 part_addr = r_read_le32 (part_header + 8);
		
		if (part_size == 0 || current_offset + part_size > obj->size) {
			r_bin_mdt_part_free (part);
			break;
		}
		
		part->name = r_str_newf ("part_%d", part_count);
		part->paddr = current_offset;
		part->vaddr = part_addr;
		part->size = part_size;
		part->type = r_read_le32 (part_header + 12);
		part->attr = r_read_le32 (part_header + 16);
		
		// Create buffer slice for this part
		part->buf = r_buf_new_slice (obj->buf, current_offset, part_size);
		
		obj->parts[part_count] = part;
		part_count++;
		
		// Check if this part contains ELF data
		parse_elf_segments (obj, part->buf, 0);
		
		current_offset += part_size;
	}
	
	obj->nparts = part_count;
	return part_count > 0;
}

// Create new MDT object from buffer
RBinMdtObj *r_bin_mdt_new_buf(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, NULL);
	
	if (!r_bin_mdt_check (buf)) {
		return NULL;
	}
	
	RBinMdtObj *obj = R_NEW0 (RBinMdtObj);
	if (!obj) {
		return NULL;
	}
	
	obj->buf = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	
	// Read MDT header
	if (r_buf_read_at (buf, 0, (ut8*)&obj->header, sizeof(MdtImageHeader)) != sizeof(MdtImageHeader)) {
		r_bin_mdt_free (obj);
		return NULL;
	}
	
	// Initialize lists
	obj->segments = r_list_newf (free);
	obj->sections = r_list_newf (free);
	obj->symbols = r_list_newf (free);
	obj->imports = r_list_newf (free);
	obj->libs = r_list_newf (free);
	obj->relocs = r_list_newf (free);
	obj->maps = r_list_newf (free);
	obj->entries = r_list_newf (free);
	
	// Set default values
	obj->baddr = obj->header.image_dest_ptr;
	obj->big_endian = false;
	obj->bits = 32;
	obj->arch = strdup ("arm");
	obj->machine = strdup ("ARM");
	obj->os = strdup ("Qualcomm");
	
	// Parse MDT parts
	if (!parse_mdt_parts (obj)) {
		r_bin_mdt_free (obj);
		return NULL;
	}
	
	return obj;
}

// Get base address
ut64 r_bin_mdt_get_baddr(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, 0);
	return obj->baddr;
}

// Get file size
ut64 r_bin_mdt_get_size(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, 0);
	return obj->size;
}

// Get binary info
RBinInfo *r_bin_mdt_get_info(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	
	RBinInfo *info = R_NEW0 (RBinInfo);
	if (!info) {
		return NULL;
	}
	
	info->file = strdup ("mdt");
	info->bclass = strdup ("firmware");
	info->rclass = strdup ("mdt");
	info->os = strdup (obj->os ? obj->os : "Qualcomm");
	info->arch = strdup (obj->arch ? obj->arch : "arm");
	info->machine = strdup (obj->machine ? obj->machine : "ARM");
	info->subsystem = strdup ("peripheral");
	info->type = strdup ("firmware");
	info->bits = obj->bits;
	info->has_va = true;
	info->has_crypto = obj->header.signature_size > 0 || obj->header.cert_chain_size > 0;
	info->has_pi = false;
	info->has_nx = false;
	info->big_endian = obj->big_endian;
	info->dbg_info = false;
	
	return info;
}

// Get entry points
RList *r_bin_mdt_get_entries(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	
	RList *entries = r_list_newf (free);
	if (!entries) {
		return NULL;
	}
	
	// Add main entry point
	if (obj->header.image_dest_ptr > 0) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		if (entry) {
			entry->paddr = 0;
			entry->vaddr = obj->header.image_dest_ptr;
			entry->type = R_BIN_ENTRY_TYPE_PROGRAM;
			r_list_append (entries, entry);
		}
	}
	
	// Add entries from parts
	for (ut32 i = 0; i < obj->nparts; i++) {
		RBinMdtPart *part = obj->parts[i];
		if (part && part->type == MDT_SEGMENT_LOAD && part->vaddr > 0) {
			RBinAddr *entry = R_NEW0 (RBinAddr);
			if (entry) {
				entry->paddr = part->paddr;
				entry->vaddr = part->vaddr;
				entry->type = R_BIN_ENTRY_TYPE_PROGRAM;
				r_list_append (entries, entry);
			}
		}
	}
	
	return entries;
}

// Get sections
RList *r_bin_mdt_get_sections(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	
	RList *sections = r_list_newf (free);
	if (!sections) {
		return NULL;
	}
	
	// Create sections from MDT parts
	for (ut32 i = 0; i < obj->nparts; i++) {
		RBinMdtPart *part = obj->parts[i];
		if (!part) {
			continue;
		}
		
		RBinSection *section = R_NEW0 (RBinSection);
		if (!section) {
			continue;
		}
		
		section->name = strdup (part->name);
		section->paddr = part->paddr;
		section->vaddr = part->vaddr;
		section->size = part->size;
		section->vsize = part->size;
		section->add = true;
		section->has_strings = true;
		
		// Set permissions based on part type
		switch (part->type) {
		case MDT_SEGMENT_LOAD:
			section->perm = R_PERM_RX;
			break;
		case MDT_SEGMENT_DYNAMIC:
			section->perm = R_PERM_RW;
			break;
		default:
			section->perm = R_PERM_R;
			break;
		}
		
		r_list_append (sections, section);
	}
	
	// Add signature section if present
	if (obj->header.signature_size > 0) {
		RBinSection *section = R_NEW0 (RBinSection);
		if (section) {
			section->name = strdup ("signature");
			section->paddr = obj->header.signature_ptr - obj->baddr;
			section->vaddr = obj->header.signature_ptr;
			section->size = obj->header.signature_size;
			section->vsize = obj->header.signature_size;
			section->perm = R_PERM_R;
			section->add = true;
			section->has_strings = false;
			r_list_append (sections, section);
		}
	}
	
	// Add certificate chain section if present
	if (obj->header.cert_chain_size > 0) {
		RBinSection *section = R_NEW0 (RBinSection);
		if (section) {
			section->name = strdup ("cert_chain");
			section->paddr = obj->header.cert_chain_ptr - obj->baddr;
			section->vaddr = obj->header.cert_chain_ptr;
			section->size = obj->header.cert_chain_size;
			section->vsize = obj->header.cert_chain_size;
			section->perm = R_PERM_R;
			section->add = true;
			section->has_strings = false;
			r_list_append (sections, section);
		}
	}
	
	return sections;
}

// Get symbols (basic implementation)
RList *r_bin_mdt_get_symbols(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	
	RList *symbols = r_list_newf (free);
	if (!symbols) {
		return NULL;
	}
	
	// Add basic symbols based on MDT structure
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		sym->name = r_bin_name_new ("_start");
		sym->paddr = 0;
		sym->vaddr = obj->header.image_dest_ptr;
		sym->size = 0;
		sym->ordinal = 0;
		sym->type = R_BIN_SYM_ENTRY;
		sym->bind = R_BIN_BIND_GLOBAL_STR;
		r_list_append (symbols, sym);
	}
	
	return symbols;
}

// Get imports (stub implementation)
RList *r_bin_mdt_get_imports(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	return r_list_newf (free);
}

// Get libraries (stub implementation)
RList *r_bin_mdt_get_libs(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	return r_list_newf (free);
}

// Get relocations (stub implementation)
RList *r_bin_mdt_get_relocs(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	return r_list_newf (free);
}

// Get memory maps
RList *r_bin_mdt_get_maps(RBinMdtObj *obj) {
	R_RETURN_VAL_IF_FAIL (obj, NULL);
	
	RList *maps = r_list_newf (free);
	if (!maps) {
		return NULL;
	}
	
	// Create maps from MDT parts
	for (ut32 i = 0; i < obj->nparts; i++) {
		RBinMdtPart *part = obj->parts[i];
		if (!part) {
			continue;
		}
		
		RBinMap *map = R_NEW0 (RBinMap);
		if (!map) {
			continue;
		}
		
		map->file = strdup (part->name);
		map->addr = part->vaddr;
		map->offset = part->paddr;
		map->size = part->size;
		
		// Set permissions based on part type
		switch (part->type) {
		case MDT_SEGMENT_LOAD:
			map->perms = R_PERM_RX;
			break;
		case MDT_SEGMENT_DYNAMIC:
			map->perms = R_PERM_RW;
			break;
		default:
			map->perms = R_PERM_R;
			break;
		}
		
		r_list_append (maps, map);
	}
	
	return maps;
}

// MBN support functions
bool r_bin_mbn_check_buffer(RBuffer *buf) {
	ut8 header[40] = {0};
	if (r_buf_read_at (buf, 0, header, sizeof(header)) != sizeof(header)) {
		return false;
	}
	
	// Basic MBN signature check
	ut32 version = r_read_le32 (header + 4);
	return version == 3; // NAND version
}

RBinMdtPart *r_bin_mdt_parse_mbn(RBuffer *buf, const char *name) {
	if (!r_bin_mbn_check_buffer (buf)) {
		return NULL;
	}
	
	RBinMdtPart *part = R_NEW0 (RBinMdtPart);
	if (!part) {
		return NULL;
	}
	
	ut8 mbn_header[40] = {0};
	r_buf_read_at (buf, 0, mbn_header, sizeof(mbn_header));
	
	part->name = strdup (name);
	part->paddr = 0;
	part->vaddr = r_read_le32 (mbn_header + 12); // vaddr from MBN header
	part->size = r_buf_size (buf);
	part->type = MDT_SEGMENT_LOAD;
	part->attr = 0;
	part->buf = r_buf_ref (buf);
	
	return part;
}