SRC_NAME = wifidog-1.30
THISDIR = $(shell pwd)

all: extract_test config_test
	$(MAKE) -C $(SRC_NAME)
	$(MAKE) -C $(SRC_NAME) install
extract_test:
	( if [ ! -d $(SRC_NAME) ] ; then \
		tar zxf $(SRC_NAME).tar.gz ; \
	fi )

config_test:
	( if [ -f ./config_done ] ; then \
		echo "the same configuration" ; \
	else \
		make configure && touch config_done; \
	fi )

configure:
	( cd $(SRC_NAME) ; \
	./autogen.sh ; \
	./configure \
		CC=$(THISDIR)/../../../toolchain-mipsel/toolchain-4.4.x/bin/mipsel-linux-uclibc-gcc \
		CXX=$(THISDIR)/../../../toolchain-mipsel/toolchain-4.4.x/bin/mipsel-linux-uclibc-g++ \
		LD=$(THISDIR)/../../../toolchain-mipsel/toolchain-4.4.x/bin/mipsel-linux-uclibc-ld \
		RANLIB=$(THISDIR)/../../../toolchain-mipsel/toolchain-4.4.x/bin/mipsel-linux-uclibc-ranlib \
		AR=$(THISDIR)/../../../toolchain-mipsel/toolchain-4.4.x/bin/mipsel-linux-uclibc-ar \
		-build=x86_64-pc-linux-gnu \
		-host=mipsel-unknown-linux-gnu \
		-target=mipsel-unknown-linux-gnu \
		-prefix=$(THISDIR)/$(SRC_NAME)/install ; \
	)

clean:
	if [ -f $(SRC_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_NAME) distclean ; \
	fi ; \
	rm -f config_done
romfs:
	#$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/install/bin/wdctl /usr/bin/wdctl
	#$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/install/bin/wifidog /usr/bin/wifidog
	#$(ROMFSINST) -p +x $(THISDIR)/wifidog.sh /usr/bin/wifidog.sh
	#cp -fP $(THISDIR)/$(SRC_NAME)/install/lib/* $(ROMFSDIR)/lib
	$(ROMFSINST) -p +x $(THISDIR)/install/bin/wdctl /usr/bin/wdctl
	$(ROMFSINST) -p +x $(THISDIR)/install/bin/wifidog /usr/bin/wifidog
	$(ROMFSINST) -p +x $(THISDIR)/wifidog.sh /usr/bin/wifidog.sh
	cp -fP $(THISDIR)/install/lib/* $(ROMFSDIR)/lib
