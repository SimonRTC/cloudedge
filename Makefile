# === Config ===
KERNEL_VERSION := 6.8
KERNEL_MINOR   := 60        # adjust if you want exact 6.8.0-60
KERNEL_URL     := https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$(KERNEL_VERSION).tar.xz
KERNEL_TAR     := linux-$(KERNEL_VERSION).tar.xz
KERNEL_SRC     := linux-$(KERNEL_VERSION)
HDR_DEST       := .libraries/include

# Your BPF source & output
BPF_SRC        := src/prog.c
BPF_OBJ        := src/router.bpf.o

# === Targets ===

all: $(BPF_OBJ)

# Step 1: download kernel tarball if missing
$(KERNEL_TAR):
	wget -O $@ $(KERNEL_URL)

# Step 2: extract kernel tarball (only if not already extracted)
$(KERNEL_SRC): $(KERNEL_TAR)
	tar xf $(KERNEL_TAR)

# Step 3: generate sanitized headers into .libraries
$(HDR_DEST): | $(KERNEL_SRC)
	cd $(KERNEL_SRC) && make headers_install INSTALL_HDR_PATH=../.libraries

# Step 4: build your BPF object using sanitized headers
$(BPF_OBJ): $(BPF_SRC) | $(HDR_DEST)
	clang -target bpf -O2 -g \
		-I$(HDR_DEST) \
		-I$(KERNEL_SRC)/include \
		-I$(KERNEL_SRC)/include/uapi \
		-I$(KERNEL_SRC)/include/generated/uapi \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Cleanup everything
clean:
	rm -rf $(BPF_OBJ) .libraries $(KERNEL_SRC) $(KERNEL_TAR)

.PHONY: all clean
