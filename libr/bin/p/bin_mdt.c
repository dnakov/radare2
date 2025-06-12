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

static bool mdt_check(RBinFile *bf, RBuffer *buf) {
	return r_bin_mdt_check_buffer(buf);
}

static bool mdt_load(RBinFile *bf, RBuffer *buf, ut64 laddr) {
	return r_bin_mdt_load_buffer(bf, bf->bo, buf, NULL);
}

RBinPlugin r_bin_plugin_mdt = {
	.meta = {
		.name = "mdt",
		.desc = "Qualcomm Peripheral Image Loader (32bit only)",
		.author = "Rot127",
		.license = "LGPL3",
	},
	.load = &mdt_load,
	.info = &mdt_info,
	.header = &r_bin_mdt_print_header,
	.maps = &r_bin_mdt_get_maps,
	.entries = &r_bin_mdt_get_entry_points,
	.check = &mdt_check,
	.destroy = &r_bin_mdt_destroy,
	.sections = &r_bin_mdt_sections,
	.symbols = &r_bin_mdt_symbols,
	.relocs = &r_bin_mdt_relocs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdt,
	.version = R2_VERSION
};
#endif