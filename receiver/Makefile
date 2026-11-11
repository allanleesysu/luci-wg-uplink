include $(TOPDIR)/rules.mk

PKG_NAME:=wg-sticky-receiver
PKG_VERSION:=1.0.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/wg-sticky-receiver
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=WireGuard incoming sticky replies
  DEPENDS:=+wireguard-tools +ip-full +firewall4 +ucode-mod-uci +python3 +conntrack
endef

define Package/wg-sticky-receiver/conffiles
/etc/config/wg_sticky
endef

define Build/Compile
endef

define Package/wg-sticky-receiver/install
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,wg-sticky-receiver))
