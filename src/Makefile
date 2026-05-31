# Makefile for Tsuki-Disk
# Tsuki-2048 Encrypted Disk Manager

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O3 -mavx2 -march=skylake -mtune=skylake \
          -funroll-loops -fomit-frame-pointer -std=gnu11
LDFLAGS = -pthread

# Check for GTK3 or GTK4, fallback to ncurses
ifeq ($(shell pkg-config --exists gtk+-3.0 && echo yes), yes)
    GUI_TYPE = gtk3
    GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
    GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)
    GUI_SRCS = gui.c
    GUI_DEFINE = -DUSE_GTK
else ifeq ($(shell pkg-config --exists gtk4 && echo yes), yes)
    GUI_TYPE = gtk4
    GTK_CFLAGS = $(shell pkg-config --cflags gtk4)
    GTK_LIBS = $(shell pkg-config --libs gtk4)
    GUI_SRCS = gui.c
    GUI_DEFINE = -DUSE_GTK
else
    GUI_TYPE = ncurses
    GTK_CFLAGS =
    GTK_LIBS = -lncurses -ltinfo
    GUI_SRCS = tui.c
    GUI_DEFINE =
endif

SODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
SODIUM_LIBS = $(shell pkg-config --libs libsodium)
ARGON2_CFLAGS = $(shell pkg-config --cflags libargon2 2>/dev/null || echo "")
ARGON2_LIBS = $(shell pkg-config --libs libargon2 2>/dev/null || echo "-largon2")
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)
LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(GTK_CFLAGS) $(SODIUM_CFLAGS) $(ARGON2_CFLAGS) $(FUSE_CFLAGS) $(LIBCRYPTO_CFLAGS) $(GUI_DEFINE) -I. -Ikyber -DKYBER_K=4
ALL_LDFLAGS = $(LDFLAGS) $(GTK_LIBS) $(SODIUM_LIBS) $(ARGON2_LIBS) $(FUSE_LIBS) $(LIBCRYPTO_LIBS) -lm

# Source files
SRCS = main.c \
       $(GUI_SRCS) \
       utils.c \
       krakken_multi.c \
       permut2048.c \
       hybrid_kem.c \
       aead.c \
       vfs.c \
       volume.c \
       sector_cache.c \
       fuse_mount.c \
       kyber/kem.c \
       kyber/indcpa.c \
       kyber/poly.c \
       kyber/polyvec.c \
       kyber/ntt.c \
       kyber/reduce.c \
       kyber/cbd.c \
       kyber/fips202.c \
       kyber/verify.c \
       kyber/symmetric-shake.c

# Object files
OBJS = $(SRCS:.c=.o)

# Verbosity control
ifeq ($(V),1)
    Q =
else
    Q = @
endif

# Target executable
TARGET = krakken-disk

# Default target
all: $(TARGET)

# Link executable
$(TARGET): $(OBJS)
	$(Q)$(CC) $(OBJS) -o $(TARGET) $(ALL_LDFLAGS)
	$(Q)bar="████████████████████"; \
	printf "\033[1;36m[$$bar]\033[0m \033[1;32m100%%\033[0m \033[1;35mLinking $(TARGET)\033[0m\n"
	@echo "Build complete: $(TARGET) (GUI: $(GUI_TYPE))"

# Compile source files
%.o: %.c
	$(Q)$(CC) $(ALL_CFLAGS) -c $< -o $@
	$(Q)current=0; \
	for obj in $(OBJS); do \
		if [ -f "$$obj" ]; then current=$$((current+1)); fi; \
	done; \
	total=$(words $(OBJS)); \
	pct=$$((current * 100 / total)); \
	num_filled=$$((current * 20 / total)); \
	num_empty=$$((20 - num_filled)); \
	bar=""; \
	i=0; while [ $$i -lt $$num_filled ]; do bar="$${bar}█"; i=$$((i+1)); done; \
	i=0; while [ $$i -lt $$num_empty ]; do bar="$${bar}░"; i=$$((i+1)); done; \
	printf "\033[1;36m[$$bar]\033[0m \033[1;32m%3d%%\033[0m Compiling \033[1;34m%s\033[0m\n" $$pct "$<"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete"

# Install (optional)
install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/
	# Install icon
	install -d $(DESTDIR)/usr/share/icons/hicolor/64x64/apps
	install -m 644 krakken-disk.svg $(DESTDIR)/usr/share/icons/hicolor/64x64/apps/
	# Install brand assets (splash and logo)
	install -d $(DESTDIR)/usr/share/krakken-disk
	install -m 644 krakken_splash.png $(DESTDIR)/usr/share/krakken-disk/
	install -m 644 krakken_logo.png $(DESTDIR)/usr/share/krakken-disk/
	# Create desktop entry for Ubuntu MATE/GTK
	install -d $(DESTDIR)/usr/share/applications
	echo "[Desktop Entry]" > $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Name=Krakken-Disk" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Comment=Krakken-2048 Encrypted Disk Manager" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Exec=$(DESTDIR)/usr/local/bin/$(TARGET)" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Icon=krakken-disk" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Terminal=false" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Type=Application" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Categories=System;Security;Utility;" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	echo "Keywords=disk;encryption;security;storage;" >> $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	chmod 644 $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	@echo "Installed to $(DESTDIR)/usr/local/bin/$(TARGET)"
	@echo "Icon installed to $(DESTDIR)/usr/share/icons/hicolor/64x64/apps/krakken-disk.svg"
	@echo "Brand assets installed to $(DESTDIR)/usr/share/krakken-disk/"
	@echo "Desktop entry created at $(DESTDIR)/usr/share/applications/krakken-disk.desktop"

# Uninstall (optional)
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	rm -f $(DESTDIR)/usr/share/applications/krakken-disk.desktop
	rm -f $(DESTDIR)/usr/share/icons/hicolor/64x64/apps/krakken-disk.svg
	rm -f $(DESTDIR)/usr/share/krakken-disk/krakken_splash.png
	rm -f $(DESTDIR)/usr/share/krakken-disk/krakken_logo.png
	rmdir --ignore-fail-on-non-empty $(DESTDIR)/usr/share/krakken-disk
	@echo "Uninstalled from $(DESTDIR)/usr/local/bin/$(TARGET)"
	@echo "Desktop entry removed from $(DESTDIR)/usr/share/applications/"
	@echo "Icon removed from $(DESTDIR)/usr/share/icons/hicolor/64x64/apps/"
	@echo "Brand assets removed from $(DESTDIR)/usr/share/krakken-disk/"

# Run the application
run: $(TARGET)
	./$(TARGET)

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists gtk4 && echo "✓ GTK4 found" || echo "✗ GTK4 not found"
	@pkg-config --exists gtk+-3.0 && echo "✓ GTK3 found" || echo "✗ GTK3 not found"
	@pkg-config --exists libsodium && echo "✓ libsodium found" || echo "✗ libsodium not found"
	@pkg-config --exists libcrypto && echo "✓ libcrypto (OpenSSL) found" || echo "✗ libcrypto (OpenSSL) not found"
	@pkg-config --exists libargon2 && echo "✓ libargon2 found" || echo "✗ libargon2 not found (may use bundled)"
	@echo "Using GUI: $(GUI_TYPE)"

# Help
help:
	@echo "Tsuki-Disk Makefile"
	@echo "=================="
	@echo "Targets:"
	@echo "  all          - Build the application (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install to /usr/local/bin and create desktop entry (requires sudo)"
	@echo "  uninstall    - Remove from /usr/local/bin and desktop entry (requires sudo)"
	@echo "  run          - Build and run the application"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  help         - Show this help message"

.PHONY: all clean install uninstall run check-deps help
