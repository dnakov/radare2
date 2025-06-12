// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <r_types.h>
#include <r_bin.h>
#include <r_util.h>
#include "../format/mdt/mdt.h"

static bool check(RBinFile *bf, RBuffer *b) {
	return r_bin_mdt_check_buffer(b);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 laddr) {
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

static RBinInfo *info(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	
	RBinInfo *ret = R_NEW0(RBinInfo);
	if (!ret) {
		return NULL;
	}
	
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("MDT");
	ret->bclass = strdup("firmware");
	ret->rclass = strdup("mdt");
	ret->machine = strdup("Hexagon");
	ret->os = strdup("Qualcomm");
	ret->arch = strdup("hexagon");
	ret->has_va = true;
	ret->has_nx = false;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->lang = NULL;
	
	return ret;
}

static void header(RBinFile *bf) {
	r_bin_mdt_print_header(bf);
}

static ut64 baddr(RBinFile *bf) {
	return 0x87400000; // Typical Qualcomm firmware base address
}

RBinPlugin r_bin_plugin_mdt = {
	.meta = {
		.name = "mdt",
		.desc = "Qualcomm Peripheral Image Loader (32bit only)",
		.author = "Rot127",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.destroy = &destroy,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.relocs = &relocs,
	.info = &info,
	.header = &header,
	.baddr = &baddr,
	.minstrlen = 0
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdt,
	.version = R2_VERSION
};
#endif