# Benchmarks

We use [`criterion`](https://crates.io/crates/criterion) as a benchmark framework. It is
* statistics driven,
* configurable,
* produces nice plots
* and is compatible with stable Rust.

To run the benchmarks, run
```
cargo bench
```

To run a specific benchmark, run
```
cargo bench -- benchmark_name
```

To test the benchmarks, run
```
cargo test --benches
```

To test a specific benchmark
```
cargo test --benches -- benchmark_name
```
