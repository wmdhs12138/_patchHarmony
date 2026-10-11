// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal, RAM-only module-loader probe for V2338A experiments.
 *
 * This module does NOT patch instructions/page tables, register a device,
 * create a proc entry, mount a filesystem, access persistent storage,
 * or resolve any kernel symbol through kallsyms.
 *
 * It still has to pass the running kernel's standard module-loader
 * validation, including vermagic, CRCs, CFI and GKI symbol protection.
 */
#include <linux/init.h>
#include <linux/module.h>

static int __init vivo_loader_probe_init(void)
{
	return 0;
}

static void __exit vivo_loader_probe_exit(void)
{
}

module_init(vivo_loader_probe_init);
module_exit(vivo_loader_probe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("V2338A minimal loader probe; no hooks and no storage writes");
MODULE_AUTHOR("V2338A ABI research");
MODULE_VERSION("0.1");
