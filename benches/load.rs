//! Sustained-load / throughput benchmark for the SESAME verify path.
//!
//! The Criterion micro-benchmarks time individual cryptographic operations.
//! This one times the *full inbound verify path with the replay cache in the
//! loop*, under sustained request volume and concurrency, which is what the
//! DoS-mitigation claim actually rests on.
//!
//! Run: cargo bench --bench load        (or: cargo run --release --bench load)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use sesame::canonical::{body_hash_hex, request_canonical};
use sesame::keys::{ChannelScope, HmacKey, StaticKeyProvider};
use sesame::replay::InMemoryReplayCache;
use sesame::tier1_hmac::sign;
use sesame::{verify_request, RequestContext, SesameConfig, SesameHeaders, Tier};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const KEY_ID: &str = "sas-east-01";
const SECRET: &[u8] = b"load-benchmark-shared-secret";
const TS: &str = "2026-02-24T18:00:00Z";
const PATH: &str = "/esam";

fn now() -> OffsetDateTime {
    OffsetDateTime::parse(TS, &Rfc3339).unwrap()
}

fn provider() -> StaticKeyProvider {
    StaticKeyProvider::new().with_signing_key(KEY_ID, HmacKey(SECRET.to_vec()), ChannelScope::all())
}

/// A pre-signed request. Signing is done up front so the measured loop is
/// verification only (what a server actually spends per inbound request).
struct Req {
    headers: SesameHeaders,
    body: Vec<u8>,
}

fn make_requests(n: usize, thread_id: usize, body_len: usize, valid: bool) -> Vec<Req> {
    let body = vec![b'x'; body_len];
    let body_hash = body_hash_hex(&body);
    (0..n)
        .map(|i| {
            // Unique nonce per request, so every request is a cache insert.
            let nonce = format!("{:016x}{:016x}", thread_id, i);
            let canonical = request_canonical("POST", PATH, TS, &nonce, &body_hash, None);
            let mut signature = sign(SECRET, &canonical);
            if !valid {
                // Corrupt the signature: exercises the early-rejection path.
                signature.replace_range(0..1, "0");
            }
            Req {
                headers: SesameHeaders {
                    version: Some("1.0".into()),
                    key_id: Some(KEY_ID.into()),
                    timestamp: Some(TS.into()),
                    nonce: Some(nonce),
                    signature: Some(signature),
                    ..Default::default()
                },
                body: body.clone(),
            }
        })
        .collect()
}

fn percentile(sorted_nanos: &[u128], p: f64) -> f64 {
    if sorted_nanos.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_nanos.len() as f64 - 1.0) * p).round() as usize;
    sorted_nanos[idx] as f64 / 1000.0 // microseconds
}

/// Phase A: how does per-request cost move as the replay cache fills?
fn phase_growth(body_len: usize) {
    println!("\n== Phase A: per-request verify cost vs. replay-cache occupancy ==");
    println!(
        "   (single thread, Tier 1, {}-byte body, 300 s window)",
        body_len
    );
    println!(
        "{:>12} {:>14} {:>12} {:>12}",
        "cache size", "batch p50 (us)", "req/s", "elapsed(s)"
    );

    let p = provider();
    let cache = InMemoryReplayCache::new(300);
    let cfg = SesameConfig::default();
    let ctx = RequestContext {
        method: "POST",
        path: PATH,
        target_channel: None,
    };
    let n = 60_000usize;
    let reqs = make_requests(n, 0, body_len, true);

    let batch = 5_000usize;
    // Hoisted: parsing the timestamp is harness setup, not verify cost.
    let now = now();
    let start_all = Instant::now();
    let mut done = 0usize;
    while done < n {
        let end = (done + batch).min(n);
        let mut lat = Vec::with_capacity(end - done);
        for r in &reqs[done..end] {
            let t0 = Instant::now();
            let _ = verify_request(&cfg, &p, &cache, &ctx, &r.headers, &r.body, now, Tier::One);
            lat.push(t0.elapsed().as_nanos());
        }
        lat.sort_unstable();
        let p50 = percentile(&lat, 0.50);
        let rate = (end - done) as f64 / (lat.iter().sum::<u128>() as f64 / 1e9);
        done = end;
        println!(
            "{:>12} {:>14.2} {:>12.0} {:>12.1}",
            done,
            p50,
            rate,
            start_all.elapsed().as_secs_f64()
        );
    }
}

/// Phase B: throughput under concurrency (shared replay cache).
fn phase_concurrency(body_len: usize, threads_list: &[usize]) {
    println!("\n== Phase B: sustained throughput under concurrency (shared cache) ==");
    println!(
        "   (Tier 1, {}-byte body, 20k requests per thread)",
        body_len
    );
    println!(
        "{:>8} {:>14} {:>12} {:>12}",
        "threads", "total req/s", "p50 (us)", "p99 (us)"
    );

    for &threads in threads_list {
        let p = provider();
        let cache = InMemoryReplayCache::new(300);
        let cfg = SesameConfig::default();
        let per = 20_000usize;
        let sets: Vec<Vec<Req>> = (0..threads)
            .map(|t| make_requests(per, t, body_len, true))
            .collect();
        let counter = AtomicUsize::new(0);

        let start = Instant::now();
        let all_lat: Vec<Vec<u128>> = std::thread::scope(|s| {
            let handles: Vec<_> = sets
                .iter()
                .map(|reqs| {
                    let (p, cache, cfg, counter) = (&p, &cache, &cfg, &counter);
                    s.spawn(move || {
                        let ctx = RequestContext {
                            method: "POST",
                            path: PATH,
                            target_channel: None,
                        };
                        let now = now();
                        let mut lat = Vec::with_capacity(reqs.len());
                        for r in reqs {
                            let t0 = Instant::now();
                            let _ = verify_request(
                                cfg,
                                p,
                                cache,
                                &ctx,
                                &r.headers,
                                &r.body,
                                now,
                                Tier::One,
                            );
                            lat.push(t0.elapsed().as_nanos());
                        }
                        counter.fetch_add(reqs.len(), Ordering::Relaxed);
                        lat
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let elapsed = start.elapsed().as_secs_f64();

        let mut lat: Vec<u128> = all_lat.into_iter().flatten().collect();
        lat.sort_unstable();
        let total = counter.load(Ordering::Relaxed);
        println!(
            "{:>8} {:>14.0} {:>12.2} {:>12.2}",
            threads,
            total as f64 / elapsed,
            percentile(&lat, 0.50),
            percentile(&lat, 0.99)
        );
    }
}

/// Phase C: early-rejection path (bad signature) - the DoS mitigation claim.
fn phase_rejection(body_len: usize) {
    println!("\n== Phase C: early rejection of invalid requests (DoS path) ==");
    println!("   (single thread, Tier 1, {}-byte body)", body_len);

    let p = provider();
    let cfg = SesameConfig::default();
    let ctx = RequestContext {
        method: "POST",
        path: PATH,
        target_channel: None,
    };
    let n = 40_000usize;

    for (label, valid) in [
        ("valid (accepted)", true),
        ("invalid sig (rejected)", false),
    ] {
        let cache = InMemoryReplayCache::new(300);
        let reqs = make_requests(n, 7, body_len, valid);
        let mut lat = Vec::with_capacity(n);
        let now = now();
        let start = Instant::now();
        for r in &reqs {
            let t0 = Instant::now();
            let _ = verify_request(&cfg, &p, &cache, &ctx, &r.headers, &r.body, now, Tier::One);
            lat.push(t0.elapsed().as_nanos());
        }
        let elapsed = start.elapsed().as_secs_f64();
        lat.sort_unstable();
        println!(
            "   {:<24} {:>10.0} req/s   p50 {:>7.2} us   p99 {:>7.2} us",
            label,
            n as f64 / elapsed,
            percentile(&lat, 0.50),
            percentile(&lat, 0.99)
        );
    }
}

fn main() {
    println!("SESAME sustained-load benchmark");
    println!(
        "cores={} ",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(0)
    );
    let body_len = 1024;
    phase_growth(body_len);
    phase_concurrency(body_len, &[1, 2, 4, 8]);
    // Payload sensitivity at fixed concurrency: body hashing dominates as the
    // ESAM document grows, so throughput should fall roughly with payload size.
    println!("\n== Phase D: payload sensitivity at 4 threads ==");
    for len in [1024usize, 4096, 16384] {
        println!("   -- {} B --", len);
        phase_concurrency(len, &[4]);
    }
    phase_rejection(body_len);
}
