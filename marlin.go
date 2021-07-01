package main

// #cgo LDFLAGS: -lmarlin_zsk -L${SRCDIR}/lib
// #include <stdbool.h>
// #include "./lib/marlin_zsk.h"
import "C"
import "fmt"

func main() {
	fmt.Printf("%v\n", C.verify(0, 25, 100, 20, 175))
	fmt.Printf("%v\n", C.verify(0, 25, 100, 24, 160))
	fmt.Printf("%v\n", C.verify(0, 25, 100, 23, 150))
	fmt.Printf("%v\n", C.verify(0, 25, 100, 25, 175))
}
