/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The hooks for the KRSI LSM are declared in this file.
 *
 * This header MUST NOT be included directly and should
 * be only used to initialize the hooks lists.
 *
 * Format:
 *
 *   KRSI_HOOK_INIT(TYPE, NAME, LSM_HOOK, KRSI_HOOK_FN)
 *
 * KRSI adds one layer of indirection between the name of the hook and the name
 * it exposes to the userspace in Security FS to prevent the userspace from
 * breaking in case the name of the hook changes in the kernel or if there's
 * another LSM hook that maps better to the represented security behaviour.
 */
KRSI_HOOK_INIT(PROCESS_EXECUTION,
	       process_execution,
	       bprm_check_security,
	       krsi_process_execution)
