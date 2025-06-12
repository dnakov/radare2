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

bool r_bin_mdt_part_new(RBinMdtPart **part, const char *name, size_t p_flags) {
	if (!part) {
		return false;
	}
	*part = R_NEW0(RBinMdtPart);
	if (!*part) {
		return false;
	}
	(*part)->name = name ? strdup(name) : NULL;
	(*part)->relocatable = p_flags & QCOM_MDT_RELOCATABLE;
	(*part)->is_layout = is_layout_bin(p_flags);
	(*part)->sections = r_list_newf((RListFree)r_bin_section_free);
	(*part)->symbols = r_list_newf((RListFree)r_bin_symbol_free);
	(*part)->relocs = r_list_newf(free);
	(*part)->sub_maps = r_list_newf(free);
	return true;
}

void r_bin_mdt_part_free(RBinMdtPart *part) {
	if (!part) {
		return;
	}
	r_buf_free(part->buf);
	switch (part->format) {
	default:
		break;
	case R_BIN_MDT_PART_ELF:
		Elf32_rz_bin_elf_free(part->obj.elf);
		break;
	case R_BIN_MDT_PART_MBN:
		free(part->obj.mbn);
		break;
	}
	free(part->map);
	r_list_free(part->relocs);
	r_list_free(part->symbols);
	r_list_free(part->sections);
	r_list_free(part->sub_maps);
	free(part->patches_vfile_name);
	free(part->relocs_vfile_name);
	free(part->name);
	free(part);
}

bool r_bin_mdt_obj_new(RBinMdtObj **obj) {
	if (!obj) {
		return false;
	}
	*obj = R_NEW0(RBinMdtObj);
	if (!*obj) {
		return false;
	}
	(*obj)->parts = r_list_newf((RListFree)r_bin_mdt_part_free);
	return true;
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
	if (!b || r_buf_size(b) <= 40) { // Minimum ELF header size
		return false;
	}
	
	if (!is_elf32(b)) {
		return false;
	}

	// Try to load as ELF and check for MDT-specific flags
	ELFOBJ *elf = Elf_(new_buf)(b, 0, false);
	if (!elf || !elf->phdr) {
		Elf_(free)(elf);
		return false;
	}

	// Check if first segment has MDT layout flags
	bool mdt_flags_set = false;
	if (elf->ehdr.e_phnum > 0) {
		mdt_flags_set = is_layout_bin(elf->phdr[0].p_flags);
	}
	
	Elf_(free)(elf);
	return mdt_flags_set;
}

bool r_bin_mdt_check_filename(const char *filename) {
	if (!filename || strlen(filename) < 4) {
		return false;
	}
	size_t len = strlen(filename);
	return filename[len - 4] == '.' && 
	       filename[len - 3] == 'm' && 
	       filename[len - 2] == 'd' && 
	       filename[len - 1] == 't';
}

static char *get_peripheral_name(const char *filename) {
	if (!r_bin_mdt_check_filename(filename)) {
		return NULL;
	}
	char *peripheral = filename ? strdup(filename) : NULL;
	if (!peripheral) {
		return NULL;
	}
	char *dot = strrchr(peripheral, '.');
	if (!dot) {
		free(peripheral);
		return NULL;
	}
	*dot = '\0';
	return peripheral;
}

static bool load_unidentified_obj_data(RBinMdtPart *part, void *segment, RBuffer *buf, RBinMap *map) {
	if (!part || !segment || !buf || !map) {
		return false;
	}
	// For unidentified segments, just keep the basic info
	part->format = R_BIN_MDT_PART_UNIDENTIFIED;
	return true;
}

static bool load_mbn_obj_data(RBinMdtPart *part, void *segment, RBuffer *buf, RBinMap *map) {
	if (!part || !segment || !buf || !map) {
		return false;
	}

	SblHeader *mbn = R_NEW0(SblHeader);
	if (!mbn) {
		return false;
	}

	// Read MBN header from buffer
	ut64 offset = 0;
	if (r_buf_read_at(buf, offset, (ut8*)mbn, sizeof(SblHeader)) != sizeof(SblHeader)) {
		free(mbn);
		return false;
	}

	// Basic validation - use existing MBN logic from bin_mbn.c
	if (mbn->version != 3) { // NAND
		free(mbn);
		return false;
	}

	part->obj.mbn = mbn;
	part->format = R_BIN_MDT_PART_MBN;
	return true;
}

static bool load_elf_obj_data(RBinMdtPart *part, void *segment_ptr, RBuffer *buf, RBinMap *map, bool big_endian) {
	if (!part || !segment_ptr || !buf || !map) {
		return false;
	}

	ELFOBJ *elf = Elf_(new_buf)(buf, 0, false);
	if (!elf) {
		R_LOG_ERROR("Failed to load segment '%s' as ELF.\n", part->name);
		return false;
	}

	part->obj.elf = elf;
	part->format = R_BIN_MDT_PART_ELF;
	
	// Create virtual file names for patches and relocs
	part->patches_vfile_name = r_str_newf("patches.%s", part->name);
	part->relocs_vfile_name = r_str_newf("relocs.%s", part->name);

	// For now, keep symbol and section extraction simple
	// TODO: Add proper vector-based symbol/section extraction later
	
	return true;
}

static RBinSection *elf_to_bin_segment(void *segment_ptr, const char *name) {
	RBinSection *bseg = R_NEW0(RBinSection);
	if (!bseg) {
		return NULL;
	}

	// Cast to Elf32_Phdr (assuming 32-bit for now)
	Elf32_Phdr *segment = (Elf32_Phdr *)segment_ptr;
	
	bseg->paddr = segment->p_paddr;
	bseg->size = segment->p_filesz;
	bseg->vsize = segment->p_memsz;
	bseg->vaddr = segment->p_vaddr;
	bseg->perm = segment->p_flags & (PF_X | PF_W | PF_R);
	bseg->is_segment = true;
	bseg->is_data = !(segment->p_flags & PF_X);
	bseg->flags = segment->p_flags;
	bseg->name = name ? strdup(name) : NULL;
	return bseg;
}

static RBinMdtPart *segment_to_mdt_part(void *segment_ptr, size_t part_num, const char *suffix_less_path, bool big_endian) {
	Elf32_Phdr *segment = (Elf32_Phdr *)segment_ptr;
	RBuffer *vfile_buffer = NULL;
	char *segment_file_path = NULL;
	RBinMdtPart *part = NULL;
	RBinMap *map = NULL;

	segment_file_path = r_str_newf("%s.b%02zu", suffix_less_path, part_num);
	if (!segment_file_path) {
		goto error;
	}

	const char *segment_name = r_file_basename(segment_file_path);
	if (!segment_name) {
		segment_name = segment_file_path;
	}

	if (!r_bin_mdt_part_new(&part, segment_name, segment->p_flags)) {
		goto error;
	}

	bool segment_file_exists = r_file_exists(segment_file_path);
	bool zero_segment = segment->p_filesz == 0;
	
	if (zero_segment && segment_file_exists) {
		R_LOG_WARN("The segment size for '%s' is 0. But the file exists. Skip loading.\n", segment_file_path);
		goto error;
	} else if (!zero_segment && !segment_file_exists) {
		R_LOG_WARN("The segment size for '%s' is 0x%x. But the file doesn't exist. Skip loading.\n", 
			   segment_file_path, segment->p_filesz);
		goto error;
	}

	// Read <name>.bNN
	vfile_buffer = zero_segment ? 
		r_buf_new_empty(segment->p_memsz) : 
		r_buf_new_file(segment_file_path, O_RDONLY, 0);
		
	if (!vfile_buffer) {
		R_LOG_ERROR("Failed to read '%s'\n", segment_file_path);
		goto error;
	}

	part->buf = vfile_buffer;

	map = R_NEW0(RBinMap);
	if (!map) {
		goto error;
	}
	map->addr = segment->p_vaddr;
	map->offset = 0;
	map->size = segment->p_filesz;
	map->perms = segment->p_flags & (PF_X | PF_W | PF_R);
	map->file = strdup(part->name);

	part->paddr = segment->p_paddr;
	part->pflags = segment->p_flags;
	part->map = map;

	// Create a section for this segment
	RBinSection *bseg = elf_to_bin_segment(segment, part->name);
	if (bseg) {
		r_list_append(part->sections, bseg);
	}

	// Determine format and load object data
	if (is_elf32(vfile_buffer)) {
		if (!load_elf_obj_data(part, segment, vfile_buffer, map, big_endian)) {
			goto error;
		}
	} else if ((segment->p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
		if (!load_mbn_obj_data(part, segment, vfile_buffer, map)) {
			R_LOG_WARN("Failed to load MBN signature segment. Header info won't be available.\n");
		}
	} else {
		if (!load_unidentified_obj_data(part, segment, vfile_buffer, map)) {
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

bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb) {
	if (!obj || !buf) {
		return false;
	}
	
	if (!r_bin_mdt_check_buffer(buf)) {
		R_LOG_ERROR("Unsupported binary.\n");
		return false;
	}

	RBinMdtObj *mdt = NULL;
	if (!r_bin_mdt_obj_new(&mdt)) {
		return false;
	}

	mdt->name = get_peripheral_name(bf->file);
	if (!mdt->name) {
		R_LOG_ERROR("Filename \"%s\" doesn't indicate it is an .mdt peripheral image.\n", bf->file);
		goto error;
	}

	mdt->header = Elf_(new_buf)(buf, 0, false);
	if (!mdt->header) {
		R_LOG_ERROR("Failed to parse .mdt ELF header.\n");
		goto error;
	}

	// Process each segment and create parts
	ELFOBJ *elf = (ELFOBJ *)mdt->header;
	for (size_t i = 0; i < elf->ehdr.e_phnum; i++) {
		RBinMdtPart *part = segment_to_mdt_part(
			&elf->phdr[i], 
			i, 
			mdt->name, 
			Elf_(is_big_endian)(elf)
		);
		if (part) {
			r_list_append(mdt->parts, part);
		}
	}

	obj->bin_obj = mdt;
	return true;

error:
	r_bin_mdt_obj_free(mdt);
	return false;
}

void r_bin_mdt_destroy(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return;
	}
	r_bin_mdt_obj_free(bf->bo->bin_obj);
}

RList *r_bin_mdt_get_maps(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *maps = r_list_newf(free);
	if (!maps) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		if (!part->sub_maps || part->is_layout) {
			// The first ELF file is always the overall firmware layout
			RBinMap *clone = R_NEW0(RBinMap);
			if (clone && part->map) {
				memcpy(clone, part->map, sizeof(RBinMap));
				clone->file = part->map->file ? strdup(part->map->file) : NULL;
				r_list_append(maps, clone);
			}
			continue;
		}

		// Add the sub maps for ELF parts
		RListIter *sub_iter;
		RBinMap *sub_map;
		r_list_foreach(part->sub_maps, sub_iter, sub_map) {
			RBinMap *clone = R_NEW0(RBinMap);
			if (clone) {
				memcpy(clone, sub_map, sizeof(RBinMap));
				clone->file = sub_map->file ? strdup(sub_map->file) : NULL;
				r_list_append(maps, clone);
			}
		}
	}
	return maps;
}

RList *r_bin_mdt_get_entry_points(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *entries = r_list_newf(free);
	if (!entries) {
		return NULL;
	}
	
	ELFOBJ *elf = (ELFOBJ *)mdt->header;
	if (!elf) {
		r_list_free(entries);
		return NULL;
	}

	RBinAddr *entry = R_NEW0(RBinAddr);
	if (!entry) {
		r_list_free(entries);
		return NULL;
	}
	
	// Get entry point from ELF header
	entry->paddr = elf->ehdr.e_entry;
	entry->vaddr = elf->ehdr.e_entry;
	entry->type = R_BIN_ENTRY_TYPE_INIT;
	entry->bits = 32;
	
	r_list_append(entries, entry);
	return entries;
}

RList *r_bin_mdt_symbols(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *symbols = r_list_newf((RListFree)r_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		if (part->symbols) {
			RListIter *sym_iter;
			RBinSymbol *sym;
			r_list_foreach(part->symbols, sym_iter, sym) {
				RBinSymbol *clone = r_bin_symbol_clone(sym);
				if (clone) {
					r_list_append(symbols, clone);
				}
			}
		}
	}
	return symbols;
}

RList *r_bin_mdt_sections(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *sections = r_list_newf((RListFree)r_bin_section_free);
	if (!sections) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		if (part->sections) {
			RListIter *sec_iter;
			RBinSection *sec;
			r_list_foreach(part->sections, sec_iter, sec) {
				RBinSection *clone = r_bin_section_clone(sec);
				if (clone) {
					r_list_append(sections, clone);
				}
			}
		}
	}
	return sections;
}

RList *r_bin_mdt_relocs(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *relocs = r_list_newf(free);
	if (!relocs) {
		return NULL;
	}
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		if (part->relocs) {
			RListIter *rel_iter;
			RBinReloc *rel;
			r_list_foreach(part->relocs, rel_iter, rel) {
				RBinReloc *clone = R_NEW0(RBinReloc);
				if (clone) {
					memcpy(clone, rel, sizeof(RBinReloc));
					r_list_append(relocs, clone);
				}
			}
		}
	}
	return relocs;
}

void r_bin_mdt_print_header(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->rbin || !bf->rbin->cb_printf) {
		return;
	}
	
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	char bits[65] = { 0 };
	size_t i = 0;
	
	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach(mdt->parts, iter, part) {
		r_str_bits64(bits, qcom_p_flags(part->pflags));
		bf->rbin->cb_printf("==== MDT Segment %zu ====\n", i);
		bf->rbin->cb_printf(" priv_p_flags: 0b%s:", bits);
		if (part->is_layout) {
			bf->rbin->cb_printf(" layout");
		}
		if (part->relocatable) {
			bf->rbin->cb_printf(" reloc");
		}
		switch (part->format) {
		default:
		case R_BIN_MDT_PART_UNIDENTIFIED:
			bf->rbin->cb_printf(" | Unidentified\n");
			break;
		case R_BIN_MDT_PART_ELF:
			bf->rbin->cb_printf(" | ELF\n");
			if (part->obj.elf) {
				bf->rbin->cb_printf(" -- ELF HEADER BEGIN -- \n");
				// Would print ELF headers here if we had the function
				bf->rbin->cb_printf(" --- ELF HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf(" ------- FAILED ------- \n");
			}
			break;
		case R_BIN_MDT_PART_MBN:
			bf->rbin->cb_printf(" | MBN signature segment\n");
			if (part->obj.mbn) {
				bf->rbin->cb_printf(" -- MBN AUTH HEADER BEGIN -- \n");
				// Print MBN header info
				SblHeader *mbn = part->obj.mbn;
				bf->rbin->cb_printf("Image ID: 0x%08x\n", mbn->load_index);
				bf->rbin->cb_printf("Version: %u\n", mbn->version);
				bf->rbin->cb_printf("Physical Address: 0x%08x\n", mbn->paddr);
				bf->rbin->cb_printf("Virtual Address: 0x%08x\n", mbn->vaddr);
				bf->rbin->cb_printf("Size: %u\n", mbn->psize);
				bf->rbin->cb_printf(" --- MBN AUTH HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf(" ------- FAILED ------- \n");
			}
			break;
		case R_BIN_MDT_PART_COMPRESSED_Q6ZIP:
			bf->rbin->cb_printf(" | Q6ZIP compressed\n");
			break;
		case R_BIN_MDT_PART_COMPRESSED_CLADE2:
			bf->rbin->cb_printf(" | CLADE2 compressed\n");
			break;
		case R_BIN_MDT_PART_COMPRESSED_ZLIB:
			bf->rbin->cb_printf(" | ZLIB compressed\n");
			break;
		}
		i++;
	}
}

// ELF integration stub functions
bool elf_check_buffer_aux(RBuffer *b) {
	return is_elf32(b);
}

void *Elf32_rz_bin_elf_new_buf(RBuffer *buf, void *opts) {
	return Elf_(new_buf)(buf, 0, false);
}

void Elf32_rz_bin_elf_free(void *elf) {
	if (elf) {
		Elf_(free)((ELFOBJ *)elf);
	}
}

bool Elf32_rz_bin_elf_is_big_endian(void *elf) {
	if (!elf) {
		return false;
	}
	return Elf_(is_big_endian)((ELFOBJ *)elf);
}

bool Elf32_rz_bin_elf_has_va(void *elf) {
	if (!elf) {
		return false;
	}
	return Elf_(has_va)((ELFOBJ *)elf);
}

bool Elf32_rz_bin_elf_has_nx(void *elf) {
	if (!elf) {
		return false;
	}
	return Elf_(has_nx)((ELFOBJ *)elf);
}

char *Elf32_rz_bin_elf_get_intrp(void *elf) {
	if (!elf) {
		return NULL;
	}
	return Elf_(intrp)((ELFOBJ *)elf);
}

char *Elf32_rz_bin_elf_get_compiler(void *elf) {
	if (!elf) {
		return NULL;
	}
	return Elf_(compiler)((ELFOBJ *)elf);
}

char *Elf32_rz_bin_elf_get_arch(void *elf) {
	if (!elf) {
		return strdup("arm");
	}
	return Elf_(get_arch)((ELFOBJ *)elf);
}

char *Elf32_rz_bin_elf_get_cpu(void *elf) {
	if (!elf) {
		return strdup("cortex");
	}
	return Elf_(get_cpu)((ELFOBJ *)elf);
}

char *Elf32_rz_bin_elf_get_machine_name(void *elf) {
	if (!elf) {
		return strdup("ARM");
	}
	return Elf_(get_machine_name)((ELFOBJ *)elf);
}