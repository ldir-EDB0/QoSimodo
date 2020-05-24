include $(TOPDIR)/rules.mk

PKG_NAME:=QoSimodo
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/QoSimodo
  CATEGORY:=Extra
  TITLE:=QoSimodo
  DEPENDS:=+libjson-c
endef

#TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -ljson-c

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/QoSimodo/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/QoSimodo $(1)/usr/bin/
endef

$(eval $(call BuildPackage,QoSimodo))

