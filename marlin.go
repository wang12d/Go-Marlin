package main

// #cgo LDFLAGS: -lmarlin_zsk -L${SRCDIR}/lib
// #include <stdbool.h>
// #include "./lib/marlin_zsk.h"
import "C"
import "fmt"

func main() {
	fmt.Printf("%v\n", C.verify())
}
