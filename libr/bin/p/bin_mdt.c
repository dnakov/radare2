/* radare2 - LGPL - Copyright 2024 - User */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/mdt/mdt.h"

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	return r_bin_mdt_check (b);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	RBinMdtObj *obj = r_bin_mdt_new_buf (b);
	if (!obj) {
		return false;
	}
	bf->bo->bin_obj = obj;
	return true;
}

static void destroy(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		r_bin_mdt_free ((RBinMdtObj *)bf->bo->bin_obj);
		bf->bo->bin_obj = NULL;
	}
}

static ut64 baddr(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_baddr (obj) : 0;
}

static RList *entries(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_entries (obj) : NULL;
}

static RList *sections(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_sections (obj) : NULL;
}

static RList *symbols(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_symbols (obj) : NULL;
}

static RList *imports(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_imports (obj) : NULL;
}

static RList *libs(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_libs (obj) : NULL;
}

static RList *relocs(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_relocs (obj) : NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_info (obj) : NULL;
}

static ut64 size(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_size (obj) : 0;
}

static RList *maps(RBinFile *bf) {
	RBinMdtObj *obj = bf->bo->bin_obj;
	return obj ? r_bin_mdt_get_maps (obj) : NULL;
}

RBinPlugin r_bin_plugin_mdt = {
	.meta = {
		.name = "mdt",
		.desc = "Qualcomm peripheral firmware images loader",
		.author = "User",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.libs = &libs,
	.relocs = &relocs,
	.info = &info,
	.size = &size,
	.maps = &maps,
	.minstrlen = 10,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdt,
	.version = R2_VERSION
};
#endif