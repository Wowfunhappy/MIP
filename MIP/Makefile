# Mavericks (OS X 10.9) port of MIP's build.
#
# Differences from upstream, all forced by 10.9 or its toolchain (Xcode 6):
#  - MIP_ROOT is /usr/share/mip. Like /usr/lib, it is readable (and loadable)
#    from every sandboxed process on 10.9, including Safari's WebContent.
#  - No injectd: launchservicesd on 10.9 runs as root without a sandbox and
#    can take task ports itself (injector/direct_inject.c).
#  - Payload binaries are extracted with tools/payload2bin.py, not gobjcopy.
#  - Code signing is optional; 10.9 has no library validation.
#  - Installed with a .pkg (`make pkg` builds build/MIP.pkg), not `make install`.

.SECONDARY:
.PHONY: all pkg uninstall clean

SYSROOT ?= $(shell xcrun --show-sdk-path 2> /dev/null)
MIN_OS := -mmacosx-version-min=10.9
CFLAGS := -g $(MIN_OS) -isysroot $(SYSROOT) -I. -Werror -O3 -Wno-unknown-warning-option -Wno-deprecated-declarations
LDFLAGS := -g $(MIN_OS) -isysroot $(SYSROOT)
SUBSTITUTE ?= YES
MIP_ROOT ?= /usr/share/mip
PKG_ID := com.Wowfunhappy.MavMIP
PKG_VERSION ?= $(shell date +%Y.%m.%d)

ifneq ($(SUBSTITUTE),YES)
ifneq ($(SUBSTITUTE),NO)
$(error SUBSTITUTE must be either YES or NO)
endif
endif

LOADER_SOURCES := loader/loader.m loader/simbl_compat.m
ifeq ($(SUBSTITUTE),YES)
SUBSTITUTE_CFLAGS := -Ithird-party/substitute/lib -Ithird-party/substitute/vendor -Icompat -DMIP_MAVERICKS=1
LOADER_SOURCES += $(shell find third-party/substitute -name "*.c" -o -name "*.S")
endif

ifneq ($(SIGN_IDENTITY),)
CODESIGN_TARGET := codesign -f -s "$(SIGN_IDENTITY)"
else
CODESIGN_TARGET := @true
endif

all: build/lsdinjector.dylib build/loader.dylib build/inject

build/lsdinjector.dylib: build/injector/lsd_injector.c.o build/injector/direct_inject.c.o build/injector/injector.o
	$(CC) $(LDFLAGS) -arch x86_64 $^ -lbsm -shared -o $@
	$(CODESIGN_TARGET) $@

build/loader.dylib: $(LOADER_SOURCES) loader/loader.h loader/simbl_compat.h
	$(CC) $(CFLAGS) $(SUBSTITUTE_CFLAGS) $(LDFLAGS) -install_name $(MIP_ROOT)/loader.dylib -framework Foundation -shared -arch x86_64 -arch i386 $(filter %.m %.c %.S,$^) -o $@
	$(CODESIGN_TARGET) $@

build/inject: build/injector/inject.c.o build/injector/direct_inject.c.o build/injector/injector.o
	$(CC) $(LDFLAGS) -arch x86_64 $^ -o $@
	$(CODESIGN_TARGET) $@

build/injector/injector.o: build/injector/inject/inject.c.o build/injector/payloads/injected_x86_64.c.bin build/injector/payloads/injected_i386.c.bin
	ld -r -arch x86_64 $(filter %.o,$^) -o $@ \
		-sectcreate __INJ_x86_64 __inj_x86_64 build/injector/payloads/injected_x86_64.c.bin \
		-sectcreate __INJ_i386 __inj_i386 build/injector/payloads/injected_i386.c.bin

build/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -arch x86_64 -c $< -o $@

PAYLOAD_FLAGS := -g $(MIN_OS) -isysroot $(SYSROOT) -I. -Oz -fno-exceptions -fno-asynchronous-unwind-tables \
	-fno-builtin -nostdlib -shared -Wl,-undefined,error \
	-Wl,-sectalign,__TEXT,__text,1000 -Wl,-order_file,injector/payloads/order

build/injector/payloads/injected_%.c.dylib: injector/payloads/injected_%.c injector/payloads/injected.h
	mkdir -p $(dir $@)
	$(CC) $(PAYLOAD_FLAGS) -arch $* $< -o $@

build/injector/payloads/%.bin: build/injector/payloads/%.dylib tools/payload2bin.py
	python tools/payload2bin.py $< $@

PKGROOT := build/pkgroot

pkg: all package/Distribution.in package/scripts/postinstall
	rm -rf $(PKGROOT) build/component build/MIP.pkg
	mkdir -p $(PKGROOT)$(MIP_ROOT)/Bundles $(PKGROOT)/usr/local/bin $(PKGROOT)/usr/local/include/mip \
		$(PKGROOT)/Library/LaunchDaemons build/component
	cp build/lsdinjector.dylib build/loader.dylib $(PKGROOT)$(MIP_ROOT)/
	cp build/inject $(PKGROOT)/usr/local/bin/
	cp loader/loader_public.h $(PKGROOT)/usr/local/include/mip/loader.h
	sed "s=@MIP_ROOT@=$(MIP_ROOT)=g" local.lsdinjector.plist > $(PKGROOT)/Library/LaunchDaemons/local.lsdinjector.plist
	chmod -R u=rwX,go=rX $(PKGROOT)
	pkgbuild --root $(PKGROOT) --identifier $(PKG_ID) --version $(PKG_VERSION) --install-location / \
		--scripts package/scripts build/component/MIP.pkg
	@# As in the SIMBL package: leave the permissions of existing folders (/usr/local,
	@# /Library/Application Support, ...) alone, and ask for a logout.
	rm -rf build/component/expanded
	pkgutil --expand build/component/MIP.pkg build/component/expanded
	sed -i '' -e 's/overwrite-permissions="true"/overwrite-permissions="false"/' \
		-e 's/postinstall-action="none"/postinstall-action="logout"/' build/component/expanded/PackageInfo
	rm build/component/MIP.pkg
	pkgutil --flatten build/component/expanded build/component/MIP.pkg
	rm -rf build/component/expanded
	sed -e "s/@VERSION@/$(PKG_VERSION)/" -e "s/@KBYTES@/$$(du -sk $(PKGROOT) | cut -f1)/" \
		package/Distribution.in > build/Distribution
	productbuild --distribution build/Distribution --resources package/Resources \
		--package-path build/component build/MIP.pkg

uninstall:
	-sudo launchctl unload /Library/LaunchDaemons/local.lsdinjector.plist
	-sudo rm -f /Library/LaunchDaemons/local.lsdinjector.plist
	-sudo rm -rf $(MIP_ROOT)
	-sudo rm -rf /usr/local/include/mip
	-sudo rm -f /usr/local/bin/inject
	-sudo pkgutil --forget $(PKG_ID)
	@echo "Uninstalled. launchservicesd keeps the injector until it restarts (log out, or reboot)."

clean:
	rm -rf build
