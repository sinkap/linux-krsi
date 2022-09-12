// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

extern struct bpf_key *bpf_lookup_user_key(u32 serial, u64 flags) __ksym;
extern struct bpf_key *bpf_lookup_system_key(u64 id) __ksym;
extern void bpf_key_put(struct bpf_key *key) __ksym;
extern int bpf_verify_pkcs7_signature(struct bpf_dynptr_kern *data_ptr,
				      struct bpf_dynptr_kern *sig_ptr,
				      struct bpf_key *trusted_keyring) __ksym;

u32 monitored_pid;
u32 num_successful_sigs;
u32 system_keyring_id;

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bpf_prog_verify")
int BPF_PROG(bpf_verify, struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	u32 data_size = aux->prog->len * sizeof(struct bpf_insn);
	struct bpf_key *trusted_keyring;
	struct data *data_val;
	int ret, zero = 0;
	u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	if (aux->is_kernel)
		return 0;

	trusted_keyring = bpf_lookup_system_key(system_keyring_id);
	if (!trusted_keyring)
		return -EINVAL;

	ret = bpf_verify_pkcs7_signature(&aux->sig_info.data_ptr, &aux->sig_info.sig_ptr,
					 trusted_keyring);
	if (ret == 0)
		num_successful_sigs++;

	bpf_key_put(trusted_keyring);
out:
	return ret;
}
