// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail};
use arrayvec::ArrayVec;
use clap::Parser;
use std::fs;
use std::time::{Duration, Instant};

use serde::Deserialize;

use cryptotest_commands::commands::CryptotestCommand;
use cryptotest_commands::uov_commands::{
    CryptotestUovKeygenData, CryptotestUovOutput, CryptotestUovPkChunk, CryptotestUovSignData,
    CryptotestUovVerifyData, UovSubcommand,
};

use opentitanlib::app::TransportWrapper;
use opentitanlib::console::spi::SpiConsoleDevice;
use opentitanlib::execute_test;
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::test_utils::rpc::{ConsoleRecv, ConsoleSend};
use opentitanlib::uart::console::UartConsole;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    init: InitializeTest,

    #[arg(long, value_parser = humantime::parse_duration, default_value = "60s")]
    timeout: Duration,

    #[arg(long, num_args = 1..)]
    uov_json: Vec<String>,

    /// Tag for the result lines, e.g. the tier.
    #[arg(long, default_value = "")]
    label: String,

    /// Skip cases with a lower test_case_id, to resume a run.
    #[arg(long, default_value_t = 0)]
    from_case: usize,

    /// Skip cases with this or a higher test_case_id.
    #[arg(long, default_value_t = usize::MAX)]
    to_case: usize,
}

#[derive(Debug, Deserialize)]
struct UovTestCase {
    vendor: String,
    test_case_id: usize,
    operation: String,
    parameter_set: String,
    #[serde(default)]
    sk_seed: Vec<u8>,
    #[serde(default)]
    pk: Vec<u8>,
    #[serde(default)]
    message: Vec<u8>,
    #[serde(default)]
    salt: Vec<u8>,
    #[serde(default)]
    signature: Vec<u8>,
    #[serde(default)]
    expected_hash: Vec<u8>,
    result: bool,
}

// Must match uov_commands.h.
const MAX_SEED: usize = 32;
const MAX_SALT: usize = 16;
const MAX_MSG: usize = 3300;
const MAX_SIG: usize = 160;
const MAX_PK_CHUNK: usize = 2048;
const HASH_BYTES: usize = 32;

// Declaration order of uov_param_t in uov_commands.h.
fn param_of(name: &str) -> Result<u32> {
    match name {
        "Ip" => Ok(0),
        "Is" => Ok(1),
        "Ip3" => Ok(2),
        _ => bail!("Unsupported UOV parameter set: {name}"),
    }
}

/// Stream a public key as chunks, the last one short.
///
/// The device derives their number from the `pk_len` it was just told. Each
/// chunk serialises to ~7 KB of JSON and a key runs to 22 of them, so the log
/// level goes down for the duration.
fn send_pk(pk: &[u8], spi: &SpiConsoleDevice) -> Result<()> {
    let level = log::max_level();
    log::set_max_level(log::LevelFilter::Warn);
    for part in pk.chunks(MAX_PK_CHUNK) {
        let mut data: ArrayVec<u8, MAX_PK_CHUNK> = ArrayVec::new();
        data.try_extend_from_slice(part)?;
        CryptotestUovPkChunk {
            data,
            len: part.len(),
        }
        .send(spi)?;
    }
    log::set_max_level(level);
    Ok(())
}

fn run_testcase(t: &UovTestCase, opts: &Opts, spi: &SpiConsoleDevice) -> Result<()> {
    log::info!(
        "vendor: {}, parameter set: {}, operation: {}, test case: {}, expect {}",
        t.vendor,
        t.parameter_set,
        t.operation,
        t.test_case_id,
        if t.result { "accept" } else { "reject" }
    );

    let param = param_of(&t.parameter_set)?;

    CryptotestCommand::Uov.send(spi)?;

    match t.operation.as_str() {
        "keygen" => {
            UovSubcommand::UovKeygen.send(spi)?;
            let mut sk_seed: ArrayVec<u8, MAX_SEED> = ArrayVec::new();
            sk_seed.try_extend_from_slice(&t.sk_seed)?;
            CryptotestUovKeygenData {
                parameter_set: param,
                sk_seed,
                sk_seed_len: t.sk_seed.len(),
            }
            .send(spi)?;
        }
        "sign" => {
            UovSubcommand::UovSign.send(spi)?;
            let mut sk_seed: ArrayVec<u8, MAX_SEED> = ArrayVec::new();
            sk_seed.try_extend_from_slice(&t.sk_seed)?;
            let mut message: ArrayVec<u8, MAX_MSG> = ArrayVec::new();
            message.try_extend_from_slice(&t.message)?;
            let mut salt: ArrayVec<u8, MAX_SALT> = ArrayVec::new();
            salt.try_extend_from_slice(&t.salt)?;
            CryptotestUovSignData {
                parameter_set: param,
                sk_seed,
                sk_seed_len: t.sk_seed.len(),
                message,
                message_len: t.message.len(),
                salt,
                salt_len: t.salt.len(),
            }
            .send(spi)?;
        }
        "verify" => {
            UovSubcommand::UovVerify.send(spi)?;
            let mut message: ArrayVec<u8, MAX_MSG> = ArrayVec::new();
            message.try_extend_from_slice(&t.message)?;
            let mut signature: ArrayVec<u8, MAX_SIG> = ArrayVec::new();
            signature.try_extend_from_slice(&t.signature)?;
            CryptotestUovVerifyData {
                parameter_set: param,
                message,
                message_len: t.message.len(),
                signature,
                signature_len: t.signature.len(),
                pk_len: t.pk.len(),
            }
            .send(spi)?;
            send_pk(&t.pk, spi)?;
        }
        op => bail!("Unsupported UOV operation: {op}"),
    }

    let out = CryptotestUovOutput::recv(spi, opts.timeout, false, false)?;
    if out.success != t.result {
        bail!(
            "{} {} case {}: expected success={}, got {}",
            t.parameter_set,
            t.operation,
            t.test_case_id,
            t.result,
            out.success
        );
    }
    if t.result
        && !t.expected_hash.is_empty()
        && out.hash[..HASH_BYTES] != t.expected_hash[..]
    {
        bail!(
            "{} {} case {}: SHA3-256 expected {}, got {}",
            t.parameter_set,
            t.operation,
            t.test_case_id,
            hex::encode(&t.expected_hash),
            hex::encode(&out.hash[..HASH_BYTES])
        );
    }
    Ok(())
}

fn test_uov(opts: &Opts, transport: &TransportWrapper) -> Result<()> {
    let spi = transport.spi("BOOTSTRAP")?;
    let spi_console = SpiConsoleDevice::new(&*spi, None, /*ignore_frame_num=*/ false)?;
    let _ = UartConsole::wait_for(&spi_console, r"Running [^\r\n]*", opts.timeout)?;

    for file in &opts.uov_json {
        let raw = fs::read_to_string(file)?;
        let tests: Vec<UovTestCase> = serde_json::from_str(&raw)?;
        let (mut passed, mut total) = (0, 0);
        let start = Instant::now();
        for t in tests.iter().filter(|t| (opts.from_case..opts.to_case).contains(&t.test_case_id)) {
            let t0 = Instant::now();
            total += 1;
            let r = run_testcase(t, opts, &spi_console);
            let verdict = if r.is_ok() { "PASS" } else { "FAIL" };
            // One grep-able line per case; the report is built from these.
            println!(
                "UOV_KAT_CASE {} {} {} {} {} {} {:.3}",
                opts.label,
                t.parameter_set,
                t.operation,
                t.test_case_id,
                if t.result { "accept" } else { "reject" },
                verdict,
                t0.elapsed().as_secs_f64()
            );
            r?;
            passed += 1;
        }
        println!(
            "UOV_KAT_FILE {} {} {}/{} {:.1}",
            opts.label,
            file,
            passed,
            total,
            start.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    opts.init.init_logging();

    let transport = opts.init.init_target()?;
    execute_test!(test_uov, &opts, &transport);
    Ok(())
}
