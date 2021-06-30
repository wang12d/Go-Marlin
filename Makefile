build: libmarlin_zsk.so
	cp marlin_zsk/target/release/libmarlin_zsk.so lib/
	go build -ldflags="-r $(shell pwd)/lib" -o a.out marlin.go

libmarlin_zsk.so:
	cd marlin_zsk && cargo build --release

clean:
	rm lib/libmarlin_zsk.so a.out