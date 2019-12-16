.. SPDX-License-Identifier: GPL-2.0+
.. Copyright 2019 Google LLC.

==========================
eBPF Linux Security Module
==========================

This LSM allows runtime instrumentation of the LSM hooks by privileged users to
implement system-wide MAC (Mandatory Access Control) and Audit policies using
eBPF. The LSM is priveleged and stackable and requires both ``CAP_SYS_ADMIN``
and ``CAP_MAC_ADMIN`` for the loading of BPF programs and modification of MAC
policies respectively.

eBPF Programs
==============

`eBPF (extended BPF) <https://cilium.readthedocs.io/en/latest/bpf>`_ is a
virtual machine-like construct in the Linux Kernel allowing the execution of
verifiable, just-in-time compiled byte code at various points in the Kernel.

The eBPF LSM adds a new type, ``BPF_PROG_TYPE_LSM``, of eBPF programs which
have the following characteristics:

	* Multiple eBPF programs can be attached to the same LSM hook.
	* LSM hooks can return an ``-EPERM`` to indicate the decision of the
	  MAC policy being enforced or simply be used for auditing.
	* Allowing the eBPF programs to be attached to all the LSM hooks by
	  making :doc:`/bpf/btf` type information available for all LSM hooks
	  and allowing the BPF verifier to perform runtime relocations and
	  validation on the programs.

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
	};

	struct vm_area_struct {
		unsigned long start_brk, brk, start_stack;
		unsigned long vm_start, vm_end;
		struct mm_struct *vm_mm;
	};


.. note:: Only the size and the names of the fields must match the type in the
	  kernel and the order of the fields is irrelevant.

The eBPF programs can be declared using macros similar to the ``BPF_TRACE_<N>``
macros defined in `tools/testing/selftests/bpf/bpf_trace_helpers.h`_. In this
example:

	* The LSM hook takes 3 args so we use ``BPF_TRACE_3``.
	* ``"lsm/file_mprotect"`` indicates the LSM hook that the program must
	  be attached to.
	* ``mprotect_audit`` is the name of the eBPF program.

.. code-block:: c

	BPF_TRACE_3("lsm/file_mprotect", mprotect_audit,
		    struct vm_area_struct *, vma,
		    unsigned long, reqprot, unsigned long, prot)
	{
		int is_heap = 0;

		__builtin_preserve_access_index(({
			is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
				   vma->vm_end <= vma->vm_mm->brk);
		}));

		/*
		 * Return an -EPERM or Write information to the perf events buffer
	 	 * for auditing
	 	 */
	}

The ``__builtin_preserve_access_index`` is a clang primitive that allows the
BPF verifier to update the offsets for the access at runtime using the
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

The LSM creates a file in securityfs for each LSM hook to which eBPF programs
can be attached using :manpage:`bpf(2)` syscall's ``BPF_PROG_ATTACH`` operation
or more simply by using the libbpf helper ``bpf_program__attach_lsm``. In the
code shown below ``prog`` is the eBPF program loaded using ``BPF_PROG_LOAD``:


.. code-block:: c

	struct bpf_link *link;

	link = bpf_program__attach_lsm(prog);

The attachment can be verified by:

.. code-block:: console

	# cat /sys/kernel/security/bpf/file_mprotect
	mprotect_audit

If, when a program is attached, another program by the same name is already attached to the hook, that program is replaced.


.. note:: This requires that the ``BPF_F_ALLOW_OVERRIDE`` flag be passed to
	  the :manpage:`bpf(2)` syscall. If not, an ``-EEXIST`` error is returned instead.

For conveniently versioning updating programs, program names are only compared up to the first ``"__"``. Thus if a program ``mprotect_audit__v1`` is attached and then ``mprotect_audit__v2`` is attached to the same hook, the latter will *replace* the former.

The program can be detached from the LSM hook by *destroying* the ``link``
link returned by ``bpf_program__attach_lsm``:

.. code-block:: c

	link->destroy();

Examples
--------

An example eBPF program can be found in
`tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c`_ and the corresponding
userspace code in
`tools/testing/selftests/bpf/prog_tests/lsm_mprotect_audit.c`_

.. Links
.. _tools/testing/selftests/bpf/bpf_trace_helpers.h:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/selftests/bpf/bpf_trace_helpers.h
.. _tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/progs/lsm_mprotect_audit.c
.. _tools/testing/selftests/bpf/prog_tests/lsm_mprotect_audit.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/prog_tests/lsm_mprotect_audit.c
