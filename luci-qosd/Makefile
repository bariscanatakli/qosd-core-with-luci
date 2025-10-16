# SPDX-License-Identifier: MIT
include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI QoS Dashboard for QoSD
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+luci-base +qosd
PKG_LICENSE:=MIT
PKG_MAINTAINER:=Barış Can Ataklı <bariscan.atakli@hotmail.com>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt build rules
$(eval $(call BuildPackage,luci-app-qosd))

