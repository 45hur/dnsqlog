whalebone_CFLAGS := -fvisibility=hidden -fPIC
whalebone_SOURCES := \
	modules/whalebone/whalebone.c \
	modules/whalebone/cache_customlist.c \
	modules/whalebone/cache_domains.c \
	modules/whalebone/cache_iprange.c \
	modules/whalebone/cache_loader.c \
	modules/whalebone/cache_policy.c \
	modules/whalebone/crc64.c \
	modules/whalebone/file_loader.c \
	modules/whalebone/iprange.c \
	modules/whalebone/log.c \
	modules/whalebone/program.c \
	modules/whalebone/socket_srv.c
whalebone_DEPEND := $(libkres)
whalebone_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) 
$(call make_c_module,whalebone)
