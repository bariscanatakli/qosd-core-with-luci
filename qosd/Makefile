	include $(TOPDIR)/rules.mk

PKG_NAME:=qosd
PKG_RELEASE:=1
PKG_VERSION:=0.5

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/qosd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Simple QoS daemon with ubus
  DEPENDS:=+libubus +libubox +libjson-c +libuci
endef

define Package/qosd/description
QoS daemon that exposes a "qosd" ubus object with a "classify" method.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src/
endef

TARGET_CFLAGS += -D_GNU_SOURCE
TARGET_LDFLAGS +=

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) \
		-o $(PKG_BUILD_DIR)/qosd-bin \
		$(PKG_BUILD_DIR)/src/config.c \
		$(PKG_BUILD_DIR)/src/dpi_signatures.c \
		$(PKG_BUILD_DIR)/src/override_store.c \
		$(PKG_BUILD_DIR)/src/qosd.c \
		$(PKG_BUILD_DIR)/src/qosd_live.c \
		$(PKG_BUILD_DIR)/src/classifier.c \
		-lubus -lubox -ljson-c -luci
endef

define Package/qosd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qosd-bin $(1)/usr/bin/qosd-bin

	$(INSTALL_DIR) $(1)/usr/sbin
	echo '#!/bin/sh' > $(1)/usr/sbin/qosd
	echo 'exec /usr/bin/qosd-bin "$@"' >> $(1)/usr/sbin/qosd
	chmod 0755 $(1)/usr/sbin/qosd

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qosd.init $(1)/etc/init.d/qosd

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/qosd.config $(1)/etc/config/qosd

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/qosd.acl.json $(1)/usr/share/rpcd/acl.d/qosd.json
endef

$(eval $(call BuildPackage,qosd))
