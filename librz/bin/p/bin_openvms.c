// SPDX-FileCopyrightText: 2026 Muqeet-Salam <muqeetsalam168@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/openvms/openvms.h"
 
RzBinPlugin rz_bin_plugin_openvms = {
	.name = "openvms",
	.desc = "OpenVMS executable format (VAX and Alpha)",
	.license = "LGPL3",
	.check_buffer = &rz_bin_openvms_check_buffer,
	.load_buffer = &rz_bin_openvms_load_buffer,
	.destroy = &rz_bin_openvms_destroy,
	.entries = &rz_bin_openvms_entries,
	.sections = &rz_bin_openvms_sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &rz_bin_openvms_info,
	.imports = &rz_bin_openvms_imports,
	.libs = &rz_bin_openvms_libs,
	.bin_structure = &rz_bin_openvms_structure,
};
 
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_openvms,
	.version = RZ_VERSION
};
#endif
 
