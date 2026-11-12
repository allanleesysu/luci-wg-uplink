include $(TOPDIR)/rules.mk

LUCI_TITLE:=WireGuard Uplink Selection
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode +ucode-mod-uci +wireguard-tools +ip-full +resolveip +firewall4 +flock +python3
PKG_VERSION:=1.3.1
PKG_RELEASE:=2
PKG_LICENSE:=MIT
PKGARCH:=all

define Package/luci-app-wg-uplink/conffiles
/etc/config/wg_uplink
endef

include ../../luci.mk
