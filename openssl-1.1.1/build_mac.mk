.PHONY: all clean FORCE

all: .done.make
.done.make: FORCE | .done.configure
	make
	touch $@

.done.configure:
	./Configure darwin64-x86_64-cc no-threads no-shared
	touch $@
#./config

clean:
	-rm .done.

FORCE:*
