# SPDX-License-Identifier: GPL-2.0
include ../../scripts/Makefile.include
include ../../scripts/utilities.mak		# QUIET_CLEAN

KRSI_VERSION = 0
KRSI_PATCHLEVEL = 0
KRSI_EXTRAVERSION = 1

LIBKRSI_VERSION	= $(KRSI_VERSION).$(KRSI_PATCHLEVEL).$(KRSI_EXTRAVERSION)
VERSION = $(KRSI_VERSION)

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
#$(info Determined 'srctree' to be $(srctree))
endif

MAKEFLAGS += --no-print-directory
LIBFILE = $(OUTPUT)libkrsi.a

CFLAGS := $(EXTRA_WARNINGS) $(EXTRA_CFLAGS)
CFLAGS += -ggdb3 -Wall -Wextra -fPIC

LIB_TARGET	= libkrsi.a libkrsi.so.$(LIBKRSI_VERSION)
LIB_FILE	= libkrsi.a libkrsi.so*

LIB_TARGET	:= $(addprefix $(OUTPUT),$(LIB_TARGET))
LIB_FILE	:= $(addprefix $(OUTPUT),$(LIB_FILE))

all: $(LIB_TARGET)

CFLAGS += -I$(srctree)/tools/lib/
CFLAGS += -I$(srctree)/tools/lib/bpf
CFLAGS += -I$(srctree)/tools/lib/bpf
CFLAGS += -I$(srctree)/tools/include
CFLAGS += -I$(srctree)/tools/arch/$(ARCH)/include/uapi
CFLAGS += -I$(srctree)/tools/include/uapi

RM = rm -f

KRSI_IN := $(OUTPUT)libkrsi-in.o

# Rebuild libbpf from the kernel sources.
BPF_DIR = $(srctree)/tools/lib/bpf/

ifneq ($(OUTPUT),)
  BPF_PATH = $(OUTPUT)
else
  BPF_PATH = $(BPF_DIR)
endif

LIBBPF = $(BPF_PATH)libbpf.a

$(LIBBPF): FORCE
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) $(OUTPUT)libbpf.a

$(LIBBPF)-clean:
	$(call QUIET_CLEAN, libbpf)
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) clean >/dev/null


export srctree OUTPUT CC LD CFLAGS V
include $(srctree)/tools/build/Makefile.include

$(KRSI_IN): $(LIBBPF) FORCE
	@$(MAKE) $(build)=libkrsi

$(OUTPUT)libkrsi.a: $(KRSI_IN)
	$(QUIET_AR)$(RM) $@ && $(AR) rcs $@ $(LIBBPF) $(KRSI_IN)

$(OUTPUT)libkrsi.so: $(OUTPUT)libkrsi.so.$(LIBKRSI_VERSION)

$(OUTPUT)libkrsi.so.$(LIBKRSI_VERSION): $(KRSI_IN)
	$(QUIET_LINK)$(CC) --shared -Wl,-soname,libkrsi.so.$(VERSION) $^ -o $@
	@ln -sf $(@F) $(OUTPUT)libkrsi.so
	@ln -sf $(@F) $(OUTPUT)libkrsi.so.$(VERSION)

clean: $(LIBBPF)-clean
	$(call QUIET_CLEAN, libkrsi) $(RM) $(LIB_TARGET) \
		*.o *~ *.a *.so *.so.$(VERSION) .*.d .*.cmd *.pc LIBBPF-CFLAGS

FORCE:

.PHONY: clean FORCE