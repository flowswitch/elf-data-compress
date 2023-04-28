TARGETS = \
  copy \
  fill \
  lz77rle \
  packbits \
  zero \

TARGETS_ALL   = $(addprefix all_,   $(TARGETS))
TARGETS_CLEAN = $(addprefix clean_, $(TARGETS))

.PHONY: all clean $(TARGETS) $(TARGETS_ALL) $(TARGETS_CLEAN)

all: $(TARGETS_ALL)

clean: $(TARGETS_CLEAN)

hard_clean: $(TARGETS_HARD)

$(TARGETS_ALL):
	make -C $(subst all_,, $@)/decompress/ all

$(TARGETS_CLEAN):
	make -C $(subst clean_,, $@)/decompress/ clean
