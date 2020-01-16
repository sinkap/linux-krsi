.. SPDX-License-Identifier: GPL-2.0+
.. Copyright 2019 Google LLC.

================
LSM BPF Programs
================

These BPF programs allow runtime instrumentation of the LSM hooks by privileged
users to implement system-wide MAC (Mandatory Access Control) and Audit
policies using eBPF. Since these program end up modifying the MAC policies of
the system, they require both ``CAP_MAC_ADMIN`` and also require
``CAP_SYS_ADMIN`` for the loading of BPF programs.

Structure
---------

The example shows an eBPF program that can be attached to the ``file_mprotect``
LSM hook:

.. c:function:: int file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);

eBPF programs that use :doc:`/bpf/btf` do not need to include kernel headers
for accessing information from the attached eBPF program's context. They can
simply declare the structures in the eBPF program and only specify the fields
that need to be accessed.

.. code-block:: c

	struct mm_struct {
		unsigned long start_brk, brk, start_stack;
	} __attribute__((preserve_access_index));

	struct vm_area_struct {
		unsigned long start_brk, brk, start_stack;
		unsigned long vm_start, vm_end;
		struct mm_struct *vm_mm;
	} __attribute__((preserve_access_index));


.. note:: Only the size and the names of the fields must match the type in the
	  kernel and the order of the fields is irrelevant.

This can be further simplified (if one has access to the BTF information at
build time) by generating the ``vmlinux.h`` with:

.. code-block:: console

        # bpftool dump file <path-to-btf-vmlinux> format c > vmlinux.h

.. note:: ``path-to-btf-vmlinux`` can be ``/sys/kernel/btf/vmlinux`` if the
	  build environment matches the environment the BPF programs are
	  deployed in.

The ``vmlinux.h`` can then simply be included in the BPF programs without
requiring the definition of the types.

The eBPF programs can be declared using the``BPF_PROG``
macros defined in `tools/testing/selftests/bpf/bpf_trace_helpers.h`_. In this
example:

	* ``"lsm/file_mprotect"`` indicates the LSM hook that the program must
	  be attached to
	* ``mprotect_audit`` is the name of the eBPF program

.. code-block:: c

        SEC("lsm/file_mprotect")
        int BPF_PROG(mprotect_audit, struct vm_area_struct *vma,
                     unsigned long reqprot, unsigned long prot, int ret)
	{
                /* Ret is the return value from the previous BPF program
                 * or 0 if it's the first hook.
                 */
                if (ret != 0)
                        return ret;

		int is_heap;

		is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
			   vma->vm_end <= vma->vm_mm->brk);

		/* Return an -EPERM or write information to the perf events buffer
		 * for auditing
		 */
	}

The ``__attribute__((preserve_access_index))`` is a clang feature that allows
the BPF verifier to update the offsets for the access at runtime using the
:doc:`/bpf/btf` information. Since the BPF verifier is aware of the types, it
also validates all the accesses made to the various types in the eBPF program.

Loading
-------

eBPP programs can be loaded with the :manpage:`bpf(2)` syscall's
``BPF_PROG_LOAD`` operation or more simply by using the the libbpf helper
``bpf_prog_load_xattr``:


.. code-block:: c

	struct bpf_prog_load_attr attr = {
		.file = "./prog.o",
	};
	struct bpf_object *prog_obj;
	struct bpf_program *prog;
	int prog_fd;

	bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd);

Attachment to LSM Hooks
-----------------------

The LSM allows attachment of eBPF programs as LSM hooks using :manpage:`bpf(2)`
syscall's ``BPF_PROG_ATTACH`` operation or more simply by
using the libbpf helper ``bpf_program__attach_lsm``. In the code shown below
``prog`` is the eBPF program loaded using ``BPF_PROG_LOAD``:

.. code-block:: c

	struct bpf_link *link;

	link = bpf_program__attach_lsm(prog);

The program can be detached from the LSM hook by *destroying* the ``link``
link returned by ``bpf_program__attach_lsm``:

.. code-block:: c

	link->destroy();

Examples
--------

Example eBPF programs can be found in
`tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c`_ and `tools/testing/selftests/bpf/progs/lsm_mprotect_mac.c`_ and the corresponding
userspace code in `tools/testing/selftests/bpf/prog_tests/lsm_mprotect.c`_

.. Links
.. _tools/testing/selftests/bpf/bpf_trace_helpers.h:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/selftests/bpf/bpf_trace_helpers.h
.. _tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c
.. _tools/testing/selftests/bpf/progs/lsm_mprotect_mac.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/progs/lsm_mprotect_mac.c
.. _tools/testing/selftests/bpf/prog_tests/lsm_mprotect.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/prog_tests/lsm_mprotect.c
