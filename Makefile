__nmk_dir=$(CURDIR)/scripts/nmk/scripts/
export __nmk_dir

#
# No need to try to remake our Makefiles
Makefile: ;
Makefile.%: ;
scripts/%.mak: ;
$(__nmk_dir)%.mk: ;

#
# Import the build engine
include $(__nmk_dir)include.mk
include $(__nmk_dir)macro.mk

ifeq ($(origin HOSTCFLAGS), undefined)
        HOSTCFLAGS := $(CFLAGS) $(USERCFLAGS)
endif

UNAME-M := $(shell uname -m)

#
# Supported Architectures
ifneq ($(filter-out x86 arm aarch64 ppc64,$(ARCH)),)
        $(error "The architecture $(ARCH) isn't supported")
endif

# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
ifeq ($(UNAME-M),ppc64)
        error := $(error ppc64 big endian is not yet supported)
endif

#
# Architecture specific options.
ifeq ($(ARCH),arm)
        ARMV		:= $(shell echo $(UNAME-M) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
        DEFINES		:= -DCONFIG_ARMV$(ARMV)

        ifeq ($(ARMV),6)
                USERCFLAGS += -march=armv6
        endif

        ifeq ($(ARMV),7)
                USERCFLAGS += -march=armv7-a
        endif

        PROTOUFIX	:= y
endif

ifeq ($(ARCH),aarch64)
        VDSO		:= y
        DEFINES		:= -DCONFIG_AARCH64
endif

ifeq ($(ARCH),ppc64)
        LDARCH		:= powerpc:common64
        VDSO		:= y
        DEFINES		:= -DCONFIG_PPC64
endif

ifeq ($(ARCH),x86)
        LDARCH		:= i386:x86-64
        VDSO		:= y
        DEFINES		:= -DCONFIG_X86_64
endif

LDARCH ?= $(SRCARCH)
export LDARCH VDSO
export PROTOUFIX DEFINES

#
# Independent options for all tools.
DEFINES			+= -D_FILE_OFFSET_BITS=64
DEFINES			+= -D_GNU_SOURCE

WARNINGS		:= -Wall -Wformat-security

CFLAGS-GCOV		:= --coverage -fno-exceptions -fno-inline
export CFLAGS-GCOV

ifneq ($(GCOV),)
        LDFLAGS         += -lgcov
        CFLAGS          += $(CFLAGS-GCOV)
endif

ifeq ($(ASAN),1)
	CFLAGS-ASAN	:= -fsanitize=address
	export		CFLAGS-ASAN
	CFLAGS		+= $(CFLAGS-ASAN)
endif

ifneq ($(WERROR),0)
        WARNINGS	+= -Werror
endif

ifeq ($(DEBUG),1)
        DEFINES		+= -DCR_DEBUG
        CFLAGS		+= -O0 -ggdb3
else
        CFLAGS		+= -O2 -g
endif

ifeq ($(GMON),1)
        CFLAGS		+= -pg
        GMONLDOPT	+= -pg
export GMON GMONLDOPT
endif

CFLAGS			+= $(USERCFLAGS) $(WARNINGS) $(DEFINES) -iquote include/
HOSTCFLAGS		+= $(WARNINGS) $(DEFINES) -iquote include/
export CFLAGS USERCLFAGS HOSTCFLAGS

# Default target
all: criu lib
.PHONY: all

#
# Version headers.
include Makefile.versions

VERSION_HEADER		:= criu/include/version.h
GITID_FILE		:= .gitid
GITID		:= $(shell if [ -d ".git" ]; then git describe --always; fi)

# Git repository wasn't inited in CRIU folder
ifeq ($(GITID),)
        GITID := 0
else
        GITID_FILE_VALUE := $(shell if [ -f '$(GITID_FILE)' ]; then if [ `cat '$(GITID_FILE)'` = $(GITID) ]; then echo y; fi; fi)
        ifneq ($(GITID_FILE_VALUE),y)
                .PHONY: $(GITID_FILE)
        endif
endif

$(GITID_FILE):
	$(call msg-gen, $@)
	$(Q) echo "$(GITID)" > $(GITID_FILE)

$(VERSION_HEADER): Makefile.versions $(GITID_FILE)
	$(call msg-gen, $@)
	$(Q) echo "/* Autogenerated, do not edit */"			 	 > $@
	$(Q) echo "#ifndef __CR_VERSION_H__"					>> $@
	$(Q) echo "#define __CR_VERSION_H__"					>> $@
	$(Q) echo "#define CRIU_VERSION \"$(CRIU_VERSION)\""			>> $@
	$(Q) echo "#define CRIU_VERSION_MAJOR " $(CRIU_VERSION_MAJOR)		>> $@
	$(Q) echo "#define CRIU_VERSION_MINOR " $(CRIU_VERSION_MINOR)		>> $@
ifneq ($(CRIU_VERSION_SUBLEVEL),)
	$(Q) echo "#define CRIU_VERSION_SUBLEVEL " $(CRIU_VERSION_SUBLEVEL)	>> $@
endif
ifneq ($(CRIU_VERSION_EXTRA),)
	$(Q) echo "#define CRIU_VERSION_EXTRA " $(CRIU_VERSION_EXTRA)		>> $@
endif
	$(Q) echo "#define CRIU_GITID \"$(GITID)\""				>> $@
	$(Q) echo "#endif /* __CR_VERSION_H__ */"				>> $@

criu-deps	+= $(VERSION_HEADER)

#
# Setup proper link for asm headers in common code.
include/common/asm: include/common/arch/$(ARCH)/asm
	$(call msg-gen, $@)
	$(Q) ln -s ./arch/$(ARCH)/asm $@

criu-deps	+= include/common/asm

#
# Configure variables.
export CONFIG_HEADER := criu/include/config.h
ifeq ($(filter tags etags cscope clean mrproper,$(MAKECMDGOALS)),)
include Makefile.config
else
# To clean all files, enable make/build options here
export CONFIG_COMPAT := y
endif

#
# Protobuf images first, they are not depending
# on anything else.
$(eval $(call gen-built-in,images))
criu-deps	+= images/built-in.o

.PHONY: .FORCE

#
# Compel get used by CRIU, build it earlier
include Makefile.compel

#
# Next the socket CR library
#
SOCCR_A := soccr/libsoccr.a
SOCCR_CONFIG := soccr/config.h
$(SOCCR_CONFIG): $(CONFIG_HEADER)
	$(Q) test -f $@ || ln -s ../$(CONFIG_HEADER) $@
soccr/Makefile: ;
soccr/%: $(SOCCR_CONFIG) .FORCE
	$(Q) $(MAKE) $(build)=soccr $@
soccr/built-in.o: $(SOCCR_CONFIG) .FORCE
	$(Q) $(MAKE) $(build)=soccr all
$(SOCCR_A): |soccr/built-in.o
criu-deps	+= $(SOCCR_A)

#
# CRIU building done in own directory
# with slightly different rules so we
# can't use nmk engine directly (we
# build syscalls library and such).
#
# But note that we're already included
# the nmk so we can reuse it there.
criu/Makefile: ;
criu/Makefile.packages: ;
criu/Makefile.crtools: ;
criu/%: $(criu-deps) .FORCE
	$(Q) $(MAKE) $(build)=criu $@
criu: $(criu-deps)
	$(Q) $(MAKE) $(build)=criu all
.PHONY: criu

#
# Libraries next once criu it ready
# (we might generate headers and such
# when building criu itself).
lib/Makefile: ;
lib/%: criu .FORCE
	$(Q) $(MAKE) $(build)=lib $@
lib: criu
	$(Q) $(MAKE) $(build)=lib all
.PHONY: lib

clean mrproper:
	$(Q) $(MAKE) $(build)=images $@
	$(Q) $(MAKE) $(build)=criu $@
	$(Q) $(MAKE) $(build)=soccr $@
	$(Q) $(MAKE) $(build)=lib $@
	$(Q) $(MAKE) $(build)=compel $@
	$(Q) $(MAKE) $(build)=compel/plugins $@
	$(Q) $(MAKE) $(build)=lib $@
.PHONY: clean mrproper

clean-top:
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(MAKE) $(build)=test/compel clean
	$(Q) $(RM) .gitid
.PHONY: clean-top

clean: clean-top

mrproper-top: clean-top
	$(Q) $(RM) $(CONFIG_HEADER)
	$(Q) $(RM) $(SOCCR_CONFIG)
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(RM) $(COMPEL_VERSION_HEADER)
	$(Q) $(RM) include/common/asm
	$(Q) $(RM) compel/include/asm
	$(Q) $(RM) cscope.*
	$(Q) $(RM) tags TAGS
.PHONY: mrproper-top

mrproper: mrproper-top

#
# Non-CRIU stuff.
#

docs:
	$(Q) $(MAKE) -s -C Documentation all
.PHONY: docs

zdtm: all
	$(Q) MAKEFLAGS= $(MAKE) -C test/zdtm all
.PHONY: zdtm

test: zdtm
	$(Q) MAKEFLAGS= $(MAKE) -C test
.PHONY: test

#
# Generating tar requires tag matched CRIU_VERSION.
# If not found then simply use GIT's describe with
# "v" prefix stripped.
head-name := $(shell git tag -l v$(CRIU_VERSION))
ifeq ($(head-name),)
        head-name := $(shell git describe 2>/dev/null)
endif
# If no git tag could describe current commit,
# use pre-defined CRIU_VERSION with GITID (if any).
ifeq ($(head-name),)
        ifneq ($(GITID),)
                head-name := $(CRIU_VERSION)-$(GITID)
        else
                head-name := $(CRIU_VERSION)
        endif
endif
tar-name := $(shell echo $(head-name) | sed -e 's/^v//g')
criu-$(tar-name).tar.bz2:
	git archive --format tar --prefix 'criu-$(tar-name)/' $(head-name) | bzip2 > $@
dist tar: criu-$(tar-name).tar.bz2 ;
.PHONY: dist tar

TAGS_FILES_REGEXP := . -name '*.[hcS]' ! -path './.*' \( ! -path './test/*' -o -path './test/zdtm/lib/*' \)
tags:
	$(call msg-gen, $@)
	$(Q) $(RM) tags
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) -print | xargs $(CTAGS) -a
.PHONY: tags

etags:
	$(call msg-gen, $@)
	$(Q) $(RM) TAGS
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) -print | xargs $(ETAGS) -a
.PHONY: etags


cscope:
	$(call msg-gen, $@)
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
.PHONY: cscope

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	geninfo --output-filename gcov/criu.info --no-recursion criu/ && \
	cd gcov && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
.PHONY: gcov

docker-build:
	$(MAKE) -C scripts/build/ x86_64 
.PHONY: docker-build

docker-test:
	docker run --rm -it --privileged criu-x86_64 ./test/zdtm.py run -a -x tcp6 -x tcpbuf6 -x static/rtc -x cgroup
.PHONY: docker-test

help:
	@echo '    Targets:'
	@echo '      all             - Build all [*] targets'
	@echo '    * criu            - Build criu'
	@echo '      zdtm            - Build zdtm test-suite'
	@echo '      docs            - Build documentation'
	@echo '      install         - Install CRIU (see INSTALL.md)'
	@echo '      uninstall       - Uninstall CRIU'
	@echo '      dist            - Create a source tarball'
	@echo '      clean           - Clean most, but leave enough to navigate'
	@echo '      mrproper        - Delete all compiled/generated files'
	@echo '      tags            - Generate tags file (ctags)'
	@echo '      etags           - Generate TAGS file (etags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      test            - Run zdtm test-suite'
	@echo '      gcov            - Make code coverage report'
.PHONY: help

lint:
	flake8 --config=scripts/flake8.cfg test/zdtm.py

include Makefile.install

.DEFAULT_GOAL := all

# Disable implicit rules in _this_ Makefile.
.SUFFIXES:

#
# Optional local include.
-include Makefile.local
