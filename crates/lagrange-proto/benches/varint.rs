
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lagrange_proto::{varint, helpers};

fn generate_test_values() -> Vec<u32> {
    vec![
        
        0, 1, 42, 127,
        
        128, 255, 1000, 16383,
        
        16384, 100000, 1000000, u32::MAX,
    ]
}

fn bench_encode_single_u32(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_single_u32");

    for value in generate_test_values() {
        let bytes = helpers::get_varint_length_u32(value);
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("dispatch", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 5];
                b.iter(|| {
                    let len = varint::encode_to_slice(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("scalar", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 5];
                b.iter(|| {
                    let len = <u32 as lagrange_proto::varint::num::VarIntTarget>::encode_varint(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("simd", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 16];
                b.iter(|| {
                    let len = varint::encode::simd::encode_to_slice_simd(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );
    }

    group.finish();
}

fn bench_encode_single_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_single_u64");

    let test_values = vec![0u64, 127, 16383, u32::MAX as u64, u64::MAX];

    for value in test_values {
        let bytes = helpers::get_varint_length_u64(value);
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("dispatch", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 10];
                b.iter(|| {
                    let len = varint::encode_to_slice(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("scalar", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 10];
                b.iter(|| {
                    let len = <u64 as lagrange_proto::varint::num::VarIntTarget>::encode_varint(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("simd", format!("{}b_val_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 16];
                b.iter(|| {
                    let len = varint::encode::simd::encode_to_slice_simd(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );
    }

    group.finish();
}

fn bench_decode_single_u32(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_single_u32");

    for value in generate_test_values() {
        let (encoded, len) = varint::encode(value);
        let bytes = len;
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("dispatch", format!("{}b_val_{}", bytes, value)),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = varint::decode::<u32>(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("scalar", format!("{}b_val_{}", bytes, value)),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = <u32 as lagrange_proto::varint::num::VarIntTarget>::decode_varint(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("simd", format!("{}b_val_{}", bytes, value)),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = varint::decode::simd::decode_simd::<u32>(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );
    }

    group.finish();
}

fn bench_zigzag_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("zigzag");

    let test_values = vec![0i32, -1, 1, -127, 127, -1000, 1000, i32::MIN, i32::MAX];

    for value in test_values {
        group.bench_with_input(
            BenchmarkId::new("encode", value),
            &value,
            |b, &val| {
                b.iter(|| {
                    let (buf, len) = varint::encode_zigzag::<u32>(black_box(val));
                    black_box((buf, len));
                });
            },
        );

        let (encoded, _len) = varint::encode_zigzag::<u32>(value);
        group.bench_with_input(
            BenchmarkId::new("decode", value),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = varint::decode_zigzag::<u32>(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );
    }

    group.finish();
}

fn bench_protobuf_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("protobuf_simulation");

    let field_tags: Vec<u32> = (1..100).collect(); 

    let mut message = Vec::new();
    for tag in &field_tags {
        let (buf, len) = varint::encode(*tag);
        message.extend_from_slice(&buf[..len]);
    }

    group.throughput(Throughput::Bytes(message.len() as u64));

    group.bench_function("encode_field_tags_sequential", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            for tag in &field_tags {
                let (data, len) = varint::encode(black_box(*tag));
                buf.extend_from_slice(&data[..len]);
            }
            black_box(buf.len());
        });
    });

    group.bench_function("decode_field_tags_sequential", |b| {
        b.iter(|| {
            let mut consumed = 0;
            let mut count = 0;
            while consumed < message.len() && count < field_tags.len() {
                let (val, len) = varint::decode::<u32>(black_box(&message[consumed..])).unwrap();
                black_box(val);
                consumed += len;
                count += 1;
            }
            black_box(count);
        });
    });

    group.finish();
}

#[cfg(target_arch = "x86_64")]
fn bench_dispatch_overhead_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch_overhead_encode");

    let test_values = generate_test_values();

    for value in test_values {
        let bytes = helpers::get_varint_length_u32(value);
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("public_api_dispatch", format!("{}b_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 5];
                b.iter(|| {
                    let len = varint::encode_to_slice(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("direct_scalar", format!("{}b_{}", bytes, value)),
            &value,
            |b, &val| {
                let mut buf = [0u8; 5];
                b.iter(|| {
                    let len = <u32 as lagrange_proto::varint::num::VarIntTarget>::encode_varint(black_box(val), &mut buf);
                    black_box(len);
                });
            },
        );

    }

    group.finish();
}

#[cfg(target_arch = "x86_64")]
fn bench_dispatch_overhead_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch_overhead_decode");

    let test_values = generate_test_values();

    for value in test_values {
        let (encoded, len) = varint::encode(value);
        let bytes = len;
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("public_api_dispatch", format!("{}b_{}", bytes, value)),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = varint::decode::<u32>(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("direct_scalar", format!("{}b_{}", bytes, value)),
            &encoded,
            |b, buf| {
                b.iter(|| {
                    let (val, len) = <u32 as lagrange_proto::varint::num::VarIntTarget>::decode_varint(black_box(&buf[..])).unwrap();
                    black_box((val, len));
                });
            },
        );

    }

    group.finish();
}

#[cfg(target_arch = "x86_64")]
fn bench_dispatch_mechanism_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch_mechanism_cost");

    let value = 127u32; 
    group.throughput(Throughput::Elements(1));

    group.bench_function("encode_with_dispatch", |b| {
        let mut buf = [0u8; 5];
        b.iter(|| {
            let len = varint::encode_to_slice(black_box(value), &mut buf);
            black_box(len);
        });
    });

    group.bench_function("encode_without_dispatch", |b| {
        let mut buf = [0u8; 5];
        b.iter(|| {
            let len = <u32 as lagrange_proto::varint::num::VarIntTarget>::encode_varint(black_box(value), &mut buf);
            black_box(len);
        });
    });

    let (encoded, _) = varint::encode(value);

    group.bench_function("decode_with_dispatch", |b| {
        b.iter(|| {
            let (val, len) = varint::decode::<u32>(black_box(&encoded[..])).unwrap();
            black_box((val, len));
        });
    });

    group.bench_function("decode_without_dispatch", |b| {
        b.iter(|| {
            let (val, len) = <u32 as lagrange_proto::varint::num::VarIntTarget>::decode_varint(black_box(&encoded[..])).unwrap();
            black_box((val, len));
        });
    });

    group.finish();
}

#[cfg(target_arch = "x86_64")]
criterion_group!(
    benches,
    bench_encode_single_u32,
    bench_encode_single_u64,
    bench_decode_single_u32,
    bench_zigzag_encoding,
    bench_protobuf_simulation,
    bench_dispatch_overhead_encode,
    bench_dispatch_overhead_decode,
    bench_dispatch_mechanism_cost,
);

#[cfg(not(target_arch = "x86_64"))]
criterion_group!(
    benches,
    bench_encode_single_u32,
    bench_encode_single_u64,
    bench_decode_single_u32,
    bench_zigzag_encoding,
    bench_protobuf_simulation,
);

criterion_main!(benches);
