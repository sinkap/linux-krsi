# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2019 Google LLC.

obj-$(CONFIG_SECURITY_BPF) := lsm.o ops.o hooks.o

ccflags-y := -I$(srctree)/security/bpf -I$(srctree)/security/bpf/include
