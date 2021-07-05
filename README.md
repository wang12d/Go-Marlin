# Go Marlin

The go library which wrapps [Marlin](https://github.com/arkworks-rs/marlin), a zero-knowledge succinct non-interactive argument of knowledge(ZK-SNARK) written in Rust language.

> DISCLAIMER: THIS LIBRARY IS ONLY FOR LEARNING PURPOSES!

The basic ideal is to using the Rust's foregin language to first convert a **concrete** Marlin instance into a C *dynamic library*, which has smaller size (static library will work too). Then, link the go program with cgo. Only a concrete Marlin instance is created, which means you cannot specify the type of polynomial nor the type of elliptic curve.

## Usage

In the cloned repository, simple input `make build` in your favorite shell. Then run the `a.out` to run the example program.

To use GoMarlin in third package, the compiled dynamic library `lib/libmarlin_sk.so` must able to be found by `go build` to convert the code into runable.
