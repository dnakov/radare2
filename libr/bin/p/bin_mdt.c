// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <r_bin.h>
#include "../format/mdt/mdt.h"

static RBinInfo *mdt_info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0(RBinInfo);
	if (!ret) {
		return NULL;
	}
	
	RBinMdtObj *mdt = bf->bo->bin_obj;
	ret->lang = "";
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("mdt");
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	ret->big_endian = Elf32_rz_bin_elf_is_big_endian(mdt->header);
	ret->has_va = Elf32_rz_bin_elf_has_va(mdt->header);
	ret->has_nx = Elf32_rz_bin_elf_has_nx(mdt->header);
	ret->intrp = Elf32_rz_bin_elf_get_intrp(mdt->header);
	ret->compiler = Elf32_rz_bin_elf_get_compiler(mdt->header);
	ret->dbg_info = 0;
	ret->bits = 32;
	ret->arch = Elf32_rz_bin_elf_get_arch(mdt->header);
	ret->cpu = Elf32_rz_bin_elf_get_cpu(mdt->header);
	ret->machine = Elf32_rz_bin_elf_get_machine_name(mdt->header);
	return ret;
}

static bool check_buffer(RBinFile *bf, RBuffer *buf) {
	return r_bin_mdt_check_buffer(buf);
}

static bool load_buffer(RBinFile *bf, RBuffer *buf, ut64 laddr) {
	if (!bf || !bf->bo) {
		return false;
	}
	return r_bin_mdt_load_buffer(bf, bf->bo, buf, NULL);
}

static void destroy(RBinFile *bf) {
	r_bin_mdt_destroy(bf);
}

static RList *maps(RBinFile *bf) {
	return r_bin_mdt_get_maps(bf);
}

static RList *entries(RBinFile *bf) {
	return r_bin_mdt_get_entry_points(bf);
}

static RList *symbols(RBinFile *bf) {
	return r_bin_mdt_symbols(bf);
}

static RList *sections(RBinFile *bf) {
	return r_bin_mdt_sections(bf);
}

static RList *relocs(RBinFile *bf) {
	return r_bin_mdt_relocs(bf);
}

static void header(RBinFile *bf) {
	r_bin_mdt_print_header(bf);
}

RBinPlugin r_bin_plugin_mdt = {
	.meta = {
		.name = "mdt",
		.desc = "Qualcomm Peripheral Image Loader (32bit only)",
		.author = "Rot127",
		.license = "LGPL-3.0-only",
	},
	.check = &check_buffer,
	.load = &load_buffer,
	.info = &mdt_info,
	.header = &header,
	.maps = &maps,
	.entries = &entries,
	.destroy = &destroy,
	.sections = &sections,
	.symbols = &symbols,
	.relocs = &relocs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdt,
	.version = R2_VERSION
};
#endif