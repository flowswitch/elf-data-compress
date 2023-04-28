.DEFAULT_GOAL := all

CM_PLATFORMS := cortex-m0 cortex-m0plus cortex-m3 cortex-m4 cortex-m7

CROSS = arm-none-eabi-

# Compiler & Linker
CC=$(CROSS)gcc
CXX=$(CROSS)g++

# -Os -flto -ffunction-sections -fdata-sections to compile for code size
CFLAGS=-Os -ffunction-sections -fdata-sections -fno-builtin
CXXFLAGS=$(CFLAGS)

# Link for code size
GC=-Wl,--gc-sections

# Create map file
MAP=-Wl,-Map=$(NAME).map

%.bin : %.o
	$(CROSS)objcopy -O binary $< $@

# d_cmX.o template

define CM_template

d_$(1).o: decompress.c
	$(CC) -c -mthumb -mcpu=$(1) $(CFLAGS) $(LFLAGS) -o $$@ $$<
endef

$(foreach tgt,$(CM_PLATFORMS),$(eval $(call CM_template,$(tgt))))


CM_TARGETS := $(foreach tgt,$(CM_PLATFORMS),d_$(tgt).bin)

$(info $(CM_TARGETS))

.PHONY: all clean

all: $(CM_TARGETS)

clean:
	rm -f *.o *.bin
