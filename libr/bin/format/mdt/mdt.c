// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mdt.h"
#include "../elf/elf.h"
#include <r_bin.h>
#include <r_util.h>
#include <r_io.h>

static inline bool is_layout_bin(size_t p_flags) {
	return (p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT;
}

static inline bool is_elf32(RBuffer *b) {
	ut8 header[16];
	if (r_buf_read_at(b, 0, header, sizeof(header)) != sizeof(header)) {
		return false;
	}
	return memcmp(header, "\x7f" "ELF", 4) == 0 && header[4] == 1;  // ELFCLASS32
}

RBinMdtPart *r_bin_mdt_part_new(const char *name, size_t p_flags) {
	RBinMdtPart *part = R_NEW0(RBinMdtPart);
	if (!part) {
		return NULL;
	}
	part->name = name ? strdup(name) : NULL;
	part->relocatable = p_flags & QCOM_MDT_RELOCATABLE;
	part->is_layout = is_layout_bin(p_flags);
	part->sections = r_list_newf((RListFree)r_bin_section_free);
	part->symbols = r_list_newf((RListFree)r_bin_symbol_free);
	part->relocs = r_list_newf(free);
	part->sub_maps = r_list_newf(free);
	return part;
}

void r_bin_mdt_part_free(RBinMdtPart *part) {
	if (!part) {
		return;
	}
	r_bin_virtual_file_free(part->vfile);
	switch (part->format) {
	default:
		break;
	case RZ_BIN_MDT_PART_ELF:
		Elf32_rz_bin_elf_free(part->obj.elf);
		break;
	case RZ_BIN_MDT_PART_MBN:
		mbn_destroy_obj(part->obj.mbn);
		break;
	}
	free(part->map);  // RBinMap is simple struct, use free()
	r_list_free(part->relocs);
	r_list_free(part->symbols);
	r_list_free(part->sections);
	r_list_free(part->sub_maps);
	free(part->patches_vfile_name);
	free(part->relocs_vfile_name);
	free(part->name);
	free(part);
}

RBinMdtObj *r_bin_mdt_obj_new(void) {
	RBinMdtObj *obj = R_NEW0(RBinMdtObj);
	if (!obj) {
		return NULL;
	}
	obj->parts = r_list_newf((RListFree)r_bin_mdt_part_free);
	return obj;
}

void r_bin_mdt_obj_free(RBinMdtObj *obj) {
	if (!obj) {
		return;
	}
	Elf32_rz_bin_elf_free(obj->header);
	r_list_free(obj->parts);
	free(obj->name);
	free(obj);
}

bool r_bin_mdt_check_buffer(RBuffer *b) {
	R_RETURN_VAL_IF_FAIL(b, false);
	if (!is_elf32(b) || r_buf_size(b) <= 64) {  // ELF_TINY_SIZE equivalent
		return false;
	}

	// Create a minimal ELF object to check segments
	void *elf = Elf32_rz_bin_elf_new_buf(b, NULL);
	if (!elf) {
		return false;
	}
	
	// Check if any segment has MDT layout flags
	// This is a simplified check - real implementation would iterate segments
	bool has_mdt_flags = true;  // Placeholder - needs real segment checking
	
	Elf32_rz_bin_elf_free(elf);
	return has_mdt_flags;
}

static bool load_unidentified_obj_data(RBinMdtPart *part, void *segment, RBinVirtualFile *vfile, RBinMap *map) {
	R_RETURN_VAL_IF_FAIL(part && segment && vfile && map, false);
	return true;
}

static bool load_mbn_obj_data(RBinMdtPart *part, void *segment, RBinVirtualFile *vfile, RBinMap *map) {
	R_RETURN_VAL_IF_FAIL(part && segment && vfile && map, false);

	SblHeader *mbn = R_NEW0(SblHeader);
	ut64 offset = 0;
	if (!mbn || !mbn_read_sbl_header(vfile->buf, mbn, &offset)) {
		mbn_destroy_obj(mbn);
		mbn = NULL;
	}
	part->obj.mbn = mbn;
	return true;
}

// Workaround for ELF module virtual address inconsistencies
static void normalize_vaddr_of_elf(void *elf, ut64 base_vaddr) {
	if (!elf) {
		return;
	}
	// This would need proper ELF structure access in real implementation
	// For now, it's a placeholder that would update segments, sections, relocs, symbols
}

static bool load_elf_obj_data(RBinMdtPart *part, void *segment, RBinVirtualFile *vfile, RBinMap *map, bool big_endian) {
	R_RETURN_VAL_IF_FAIL(part && segment && vfile && map, false);

	void *elf = Elf32_rz_bin_elf_new_buf(vfile->buf, NULL);
	if (!elf) {
		R_LOG_ERROR("Failed to load segment '%s' as ELF.\n", part->name);
		r_buf_free(vfile->buf);
		free(map);  // RBinMap is simple struct, use free()
		free(vfile);
		return false;
	}

	part->obj.elf = elf;
	part->patches_vfile_name = r_str_newf("patches.%s", part->name);
	part->relocs_vfile_name = r_str_newf("relocs.%s", part->name);

	normalize_vaddr_of_elf(part->obj.elf, part->map->addr);

	// In real implementation, this would extract ELF maps, symbols, sections, relocs
	// For now, create basic structures
	
	return true;
}

static RBinSection *elf_to_bin_segment(void *esegment, const char *name) {
	RBinSection *bseg = R_NEW0(RBinSection);
	R_RETURN_VAL_IF_FAIL(bseg, NULL);

	// This would need proper segment structure access
	bseg->paddr = 0;     // esegment->p_paddr
	bseg->size = 0;      // esegment->p_filesz
	bseg->vsize = 0;     // esegment->p_memsz
	bseg->vaddr = 0;     // esegment->p_vaddr
	bseg->perm = R_PERM_RX;  // based on esegment->p_flags
	bseg->is_segment = true;
	bseg->name = name ? strdup(name) : NULL;
	return bseg;
}

static RBinMdtPart *segment_to_mdt_part(void *segment, size_t part_num, const char *suffix_less_path, bool big_endian) {
	RBuffer *vfile_buffer = NULL;
	char *segment_file_path = NULL;
	RBinMdtPart *part = NULL;
	RBinMap *map = NULL;
	RBinVirtualFile *vfile = NULL;

	segment_file_path = r_str_newf("%s.b%02" PFMTSZu, suffix_less_path, part_num);
	if (!segment_file_path) {
		goto error;
	}
	
	const char *segment_name = r_file_basename(segment_file_path);
	if (!segment_name) {
		segment_name = segment_file_path;
	}
	
	// In real implementation, would extract p_flags from segment
	size_t p_flags = 0;
	part = r_bin_mdt_part_new(segment_name, p_flags);

	bool segment_file_exists = r_file_exists(segment_file_path);
	// In real implementation, would extract p_filesz from segment
	ut32 p_filesz = 0;
	ut32 p_memsz = 0;
	bool zero_segment = p_filesz == 0;
	
	if (zero_segment && segment_file_exists) {
		R_LOG_WARN("The segment size for '%s' is 0. But the file exists. Skip loading.\n", segment_file_path);
		goto error;
	} else if (!zero_segment && !segment_file_exists) {
		R_LOG_WARN("The segment size for '%s' is 0x%" PFMT32x ". But the file doesn't exist. Skip loading.\n", segment_file_path, p_filesz);
		goto error;
	}

	// Read <name>.bNN
	vfile_buffer = zero_segment ? r_buf_new_empty(p_memsz) : r_buf_new_file(segment_file_path, O_RDONLY, 0);
	if (!vfile_buffer) {
		R_LOG_ERROR("Failed to read '%s'\n", segment_file_path);
		goto error;
	}

	vfile = R_NEW0(RBinVirtualFile);
	if (!vfile) {
		goto error;
	}
	vfile->buf = vfile_buffer;
	vfile->buf_owned = true;
	vfile->name = part->name ? strdup(part->name) : NULL;

	map = R_NEW0(RBinMap);
	if (!map) {
		goto error;
	}
	map->addr = 0;  // p_vaddr from segment
	map->offset = 0;
	map->size = p_filesz;
	map->perms = R_PERM_RX;  // based on p_flags
	map->file = part->name ? strdup(part->name) : NULL;

	// In real implementation, would extract values from segment
	part->paddr = 0;  // segment->p_paddr
	part->pflags = 0;  // segment->p_flags
	part->map = map;
	part->vfile = vfile;
	
	RBinSection *bseg = elf_to_bin_segment(segment, part->name);
	if (!bseg) {
		goto error;
	}
	r_list_append(part->sections, bseg);

	// Determine format and load data
	if (is_elf32(vfile->buf)) {
		part->format = RZ_BIN_MDT_PART_ELF;
		if (!load_elf_obj_data(part, segment, vfile, map, big_endian)) {
			goto error;
		}
	} else if ((part->pflags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
		part->format = RZ_BIN_MDT_PART_MBN;
		if (!load_mbn_obj_data(part, segment, vfile, map)) {
			R_LOG_WARN("Failed to load MBN signature segment. Header info won't be available.\n");
		}
	} else {
		part->format = RZ_BIN_MDT_PART_UNIDENTIFIED;
		if (!load_unidentified_obj_data(part, segment, vfile, map)) {
			goto error;
		}
	}
	
	free(segment_file_path);
	return part;

error:
	r_bin_mdt_part_free(part);
	free(segment_file_path);
	return NULL;
}

bool r_bin_mdt_check_filename(const char *filename) {
	R_RETURN_VAL_IF_FAIL(filename, false);
	if (!filename || strlen(filename) < strlen(".mdt")) {
		return false;
	}
	size_t len = strlen(filename);
	return filename[len - 4] == '.' && filename[len - 3] == 'm' && 
		   filename[len - 2] == 'd' && filename[len - 1] == 't';
}

static char *get_peripheral_name(const char *filename) {
	if (!r_bin_mdt_check_filename(filename)) {
		return NULL;
	}
	char *peripheral = filename ? strdup(filename) : NULL;
	char *dot = strrchr(peripheral, '.');
	if (!dot) {
		free(peripheral);
		return NULL;
	}
	*dot = '\0';
	return peripheral;
}

bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb) {
	R_RETURN_VAL_IF_FAIL(obj && buf, false);
	if (!r_bin_mdt_check_buffer(buf)) {
		R_LOG_ERROR("Unsupported binary.\n");
		return false;
	}
	
	RBinMdtObj *mdt = r_bin_mdt_obj_new();
	if (!mdt) {
		return false;
	}

	mdt->name = get_peripheral_name(bf->file);
	if (!mdt->name) {
		R_LOG_ERROR("Filename \"%s\" doesn't indicate it is an .mdt peripheral image.\n", bf->file);
		goto error;
	}

	mdt->header = Elf32_rz_bin_elf_new_buf(buf, NULL);
	if (!mdt->header) {
		R_LOG_ERROR("Failed to parse .mdt ELF header.\n");
		goto error;
	}

	// In real implementation, would iterate through ELF segments
	// For now, create a single dummy part
	size_t i = 0;
	RBinMdtPart *part = segment_to_mdt_part(NULL, i, mdt->name, false);
	if (part) {
		r_list_append(mdt->parts, part);
	}

	obj->bin_obj = mdt;
	return true;

error:
	r_bin_mdt_obj_free(mdt);
	return false;
}

void r_bin_mdt_destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->bo && bf->bo->bin_obj);
	r_bin_mdt_obj_free(bf->bo->bin_obj);
}

RList *r_bin_mdt_virtual_files(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *vfiles = r_list_newf((RListFree)r_bin_virtual_file_free);
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		RBinVirtualFile *clone = r_bin_virtual_file_clone(part->vfile);
		if (!clone) {
			continue;
		}
		r_list_append(vfiles, clone);
		
		if (!part->relocs) {
			continue;
		}

		if (part->patches_vfile_name && part->format == RZ_BIN_MDT_PART_ELF) {
			RBinVirtualFile *patches = R_NEW0(RBinVirtualFile);
			if (patches) {
				// In real implementation, would use part->obj.elf->buf_patched
				patches->buf = r_buf_new_empty(0);
				patches->buf_owned = false;
				patches->name = part->patches_vfile_name ? strdup(part->patches_vfile_name) : NULL;
				r_list_append(vfiles, patches);
			}
		}
		
		if (part->relocs_vfile_name) {
			ut64 reloc_size = 0;  // elf_reloc_targets_vfile_size(part->obj.elf);
			if (reloc_size) {
				RBuffer *buf = r_buf_new_empty(reloc_size);
				RBinVirtualFile *relocs = R_NEW0(RBinVirtualFile);
				if (relocs && buf) {
					relocs->buf = buf;
					relocs->buf_owned = true;
					relocs->name = part->relocs_vfile_name ? strdup(part->relocs_vfile_name) : NULL;
					r_list_append(vfiles, relocs);
				} else {
					r_buf_free(buf);
					free(relocs);
				}
			}
		}
	}
	return vfiles;
}

RList *r_bin_mdt_get_maps(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *maps = r_list_newf(free);  // RBinMap is simple struct
	if (!maps) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		if (!part->sub_maps || part->is_layout) {
			// The first ELF file is always the overall firmware layout
			RBinMap *clone = r_bin_map_clone(part->map);
			if (!clone) {
				continue;
			}
			r_list_append(maps, clone);
			continue;
		}

		// Add the patched ELF maps
		RListIter *sub_iter;
		RBinMap *sub_map;
		r_list_foreach(part->sub_maps, sub_iter, sub_map) {
			RBinMap *clone = r_bin_map_clone(sub_map);
			if (!clone) {
				continue;
			}
			r_list_append(maps, clone);
		}
	}
	return maps;
}

RList *r_bin_mdt_get_entry_points(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	// Remove unused variable warning
	RList *entries = r_list_newf(free);
	if (!entries) {
		return NULL;
	}
	
	// In real implementation, would extract entry from ELF header
	RBinAddr *entry = R_NEW0(RBinAddr);
	if (!entry) {
		r_list_free(entries);
		return NULL;
	}
	
	// Placeholder values - real implementation would extract from mdt->header
	entry->paddr = 0;
	entry->vaddr = 0;
	entry->type = R_BIN_ENTRY_TYPE_INIT;
	entry->bits = 32;
	
	r_list_append(entries, entry);
	return entries;
}

RList *r_bin_mdt_symbols(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *symbols = r_list_newf((RListFree)r_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		RListIter *sym_iter;
		RBinSymbol *symbol;
		r_list_foreach(part->symbols, sym_iter, symbol) {
			RBinSymbol *clone = r_bin_symbol_clone(symbol);
			if (clone) {
				r_list_append(symbols, clone);
			}
		}
	}
	return symbols;
}

RList *r_bin_mdt_sections(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *sections = r_list_newf((RListFree)r_bin_section_free);
	if (!sections) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		RListIter *sec_iter;
		RBinSection *section;
		r_list_foreach(part->sections, sec_iter, section) {
			RBinSection *clone = r_bin_section_clone(section);
			if (clone) {
				r_list_append(sections, clone);
			}
		}
	}
	return sections;
}

RList *r_bin_mdt_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL(bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *relocs = r_list_newf(free);  // RBinReloc is simple struct
	if (!relocs) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		RListIter *rel_iter;
		RBinReloc *reloc;
		r_list_foreach(part->relocs, rel_iter, reloc) {
			RBinReloc *clone = r_bin_reloc_clone(reloc);
			if (clone) {
				r_list_append(relocs, clone);
			}
		}
	}
	return relocs;
}

void r_bin_mdt_print_header(RBinFile *bf) {
	R_RETURN_IF_FAIL(bf && bf->bo && bf->bo->bin_obj && bf->rbin && bf->rbin->cb_printf);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	char bits[65] = { 0 };
	size_t i = 0;
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		r_str_bits64(bits, qcom_p_flags(part->pflags));
		bf->rbin->cb_printf("==== MDT Segment %" PFMTSZu " ====\n", i);
		bf->rbin->cb_printf(" priv_p_flags: 0b%s:", bits);
		if (part->is_layout) {
			bf->rbin->cb_printf(" layout");
		}
		if (part->relocatable) {
			bf->rbin->cb_printf(" reloc");
		}
		switch (part->format) {
		default:
		case RZ_BIN_MDT_PART_UNIDENTIFIED:
			bf->rbin->cb_printf(" | Unidentified\n");
			break;
		case RZ_BIN_MDT_PART_ELF:
			bf->rbin->cb_printf(" | ELF\n");
			if (part->obj.elf) {
				bf->rbin->cb_printf(" -- ELF HEADER BEGIN -- \n");
				// In real implementation: elf_headers_obj((ELFOBJ *)part->obj.elf, bf->rbin->cb_printf);
				bf->rbin->cb_printf(" --- ELF HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf(" ------- FAILED ------- \n");
			}
			break;
		case RZ_BIN_MDT_PART_MBN:
			bf->rbin->cb_printf(" | MBN signature segment\n");
			if (part->obj.mbn) {
				bf->rbin->cb_printf(" -- MBN AUTH HEADER BEGIN -- \n");
				mbn_header_obj(part->obj.mbn, bf->rbin->cb_printf);
				bf->rbin->cb_printf(" --- MBN AUTH HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf(" ------- FAILED ------- \n");
			}
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_Q6ZIP:
			bf->rbin->cb_printf(" | Q6ZIP compressed\n");
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_CLADE2:
			bf->rbin->cb_printf(" | CLADE2 compressed\n");
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_ZLIB:
			bf->rbin->cb_printf(" | ZLIB compressed\n");
			break;
		}
		i++;
	}
}

// Stub implementations for MBN support
bool mbn_check_buffer(RBuffer *buf) {
	ut8 header[40] = {0};
	if (r_buf_read_at(buf, 0, header, sizeof(header)) != sizeof(header)) {
		return false;
	}
	ut32 version = r_read_le32(header + 4);
	return version == 3; // NAND version
}

bool mbn_read_sbl_header(RBuffer *buf, SblHeader *hdr, ut64 *offset) {
	if (!mbn_check_buffer(buf) || !hdr || !offset) {
		return false;
	}
	ut8 header[40] = {0};
	if (r_buf_read_at(buf, 0, header, sizeof(header)) != sizeof(header)) {
		return false;
	}
	hdr->image_id = r_read_le32(header + 0);
	hdr->header_vsn_num = r_read_le32(header + 4);
	hdr->image_src = r_read_le32(header + 8);
	hdr->image_dest_ptr = r_read_le32(header + 12);
	hdr->image_size = r_read_le32(header + 16);
	hdr->code_size = r_read_le32(header + 20);
	hdr->signature_ptr = r_read_le32(header + 24);
	hdr->signature_size = r_read_le32(header + 28);
	hdr->cert_chain_ptr = r_read_le32(header + 32);
	hdr->cert_chain_size = r_read_le32(header + 36);
	*offset = sizeof(header);
	return true;
}

void mbn_destroy_obj(SblHeader *obj) {
	free(obj);
}

void mbn_header_obj(SblHeader *obj, PrintfCallback printf_fn) {
	if (!obj || !printf_fn) {
		return;
	}
	printf_fn("Image ID: 0x%08x\n", obj->image_id);
	printf_fn("Header Version: %u\n", obj->header_vsn_num);
	printf_fn("Image Source: 0x%08x\n", obj->image_src);
	printf_fn("Image Dest Ptr: 0x%08x\n", obj->image_dest_ptr);
	printf_fn("Image Size: %u\n", obj->image_size);
	printf_fn("Code Size: %u\n", obj->code_size);
	printf_fn("Signature Ptr: 0x%08x\n", obj->signature_ptr);
	printf_fn("Signature Size: %u\n", obj->signature_size);
	printf_fn("Cert Chain Ptr: 0x%08x\n", obj->cert_chain_ptr);
	printf_fn("Cert Chain Size: %u\n", obj->cert_chain_size);
}

// Stub implementations for ELF integration
bool elf_check_buffer_aux(RBuffer *b) {
	return is_elf32(b);
}

void *Elf32_rz_bin_elf_new_buf(RBuffer *buf, void *opts) {
	// This would return a proper ELF object in real implementation
	// For now, return a dummy pointer to indicate success
	return is_elf32(buf) ? (void *)0x1 : NULL;
}

void Elf32_rz_bin_elf_free(void *elf) {
	// In real implementation, would free ELF object
}

bool Elf32_rz_bin_elf_is_big_endian(void *elf) {
	return false; // Stub
}

bool Elf32_rz_bin_elf_has_va(void *elf) {
	return true; // Stub
}

bool Elf32_rz_bin_elf_has_nx(void *elf) {
	return false; // Stub
}

char *Elf32_rz_bin_elf_get_intrp(void *elf) {
	return NULL; // Stub
}

char *Elf32_rz_bin_elf_get_compiler(void *elf) {
	return NULL; // Stub
}

char *Elf32_rz_bin_elf_get_arch(void *elf) {
	return strdup("arm"); // Stub
}

char *Elf32_rz_bin_elf_get_cpu(void *elf) {
	return strdup("cortex"); // Stub
}

char *Elf32_rz_bin_elf_get_machine_name(void *elf) {
	return strdup("ARM"); // Stub
}

// VirtualFile helper implementations
RBinVirtualFile *r_bin_virtual_file_new(void) {
	return R_NEW0(RBinVirtualFile);
}

void r_bin_virtual_file_free(RBinVirtualFile *vf) {
	if (!vf) {
		return;
	}
	free(vf->name);
	if (vf->buf_owned) {
		r_buf_free(vf->buf);
	}
	free(vf);
}

RBinVirtualFile *r_bin_virtual_file_clone(RBinVirtualFile *vf) {
	if (!vf) {
		return NULL;
	}
	RBinVirtualFile *clone = R_NEW0(RBinVirtualFile);
	if (!clone) {
		return NULL;
	}
	clone->name = vf->name ? strdup(vf->name) : NULL;
	clone->buf = vf->buf ? r_buf_ref(vf->buf) : NULL;
	clone->buf_owned = false; // Reference, not owned
	return clone;
}

// Map helper implementations
RBinMap *r_bin_map_clone(RBinMap *map) {
	if (!map) {
		return NULL;
	}
	RBinMap *clone = R_NEW0(RBinMap);
	if (!clone) {
		return NULL;
	}
	clone->addr = map->addr;
	clone->offset = map->offset;
	clone->size = map->size;
	clone->perms = map->perms;
	clone->file = map->file ? strdup(map->file) : NULL;
	return clone;
}