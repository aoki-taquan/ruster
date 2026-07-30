use std::env;
use std::process::ExitCode;
use std::time::Duration;

use ruster_bench::{run, OutputFormat, ResultRow, RunConfig, Suite};

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-bench: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    let Some((config, format)) = parse_args(env::args().skip(1))? else {
        return Ok(());
    };
    let rows = run(&config).map_err(|error| error.to_string())?;
    if matches!(format, OutputFormat::Human | OutputFormat::Both) {
        println!(
            "# ruster-bench schema=1 suite={} seed={} samples={} sample_ms={} warmup_ms={}",
            suite_name(config.suite),
            config.seed,
            config.samples,
            config.sample_time.as_millis(),
            config.warmup_time.as_millis(),
        );
        println!("{}", ResultRow::human_header());
        for row in &rows {
            println!("{}", row.to_human_line());
        }
    }
    if matches!(format, OutputFormat::JsonLines | OutputFormat::Both) {
        for row in &rows {
            println!("{}", row.to_json_line());
        }
    }
    Ok(())
}

fn parse_args(
    mut args: impl Iterator<Item = String>,
) -> Result<Option<(RunConfig, OutputFormat)>, String> {
    let mut suite = Suite::Smoke;
    let mut format = OutputFormat::Human;
    let mut seed = None;
    let mut samples = None;
    let mut sample_time = None;
    let mut warmup_time = None;
    let mut batches = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--suite" => {
                let value = next_value(&mut args, "--suite")?;
                suite = match value.as_str() {
                    "smoke" => Suite::Smoke,
                    "datapath" => Suite::Datapath,
                    _ => return Err(format!("unknown suite {value:?}")),
                };
            }
            "--format" => {
                let value = next_value(&mut args, "--format")?;
                format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "jsonl" => OutputFormat::JsonLines,
                    "both" => OutputFormat::Both,
                    _ => return Err(format!("unknown output format {value:?}")),
                };
            }
            "--seed" => {
                seed = Some(parse_value(next_value(&mut args, "--seed")?, "--seed")?);
            }
            "--samples" => {
                samples = Some(parse_value(
                    next_value(&mut args, "--samples")?,
                    "--samples",
                )?);
            }
            "--sample-ms" => {
                let millis = parse_value(next_value(&mut args, "--sample-ms")?, "--sample-ms")?;
                sample_time = Some(Duration::from_millis(millis));
            }
            "--warmup-ms" => {
                let millis = parse_value(next_value(&mut args, "--warmup-ms")?, "--warmup-ms")?;
                warmup_time = Some(Duration::from_millis(millis));
            }
            "--batches" => {
                let value = next_value(&mut args, "--batches")?;
                batches = Some(
                    value
                        .split(',')
                        .map(|part| parse_value(part.to_owned(), "--batches"))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            "--help" | "-h" => {
                print_help();
                return Ok(None);
            }
            _ => return Err(format!("unknown argument {argument:?}; try --help")),
        }
    }
    let mut config = match suite {
        Suite::Smoke => RunConfig::smoke(),
        Suite::Datapath => RunConfig::datapath(),
    };
    config.seed = seed.unwrap_or(config.seed);
    config.samples = samples.unwrap_or(config.samples);
    config.sample_time = sample_time.unwrap_or(config.sample_time);
    config.warmup_time = warmup_time.unwrap_or(config.warmup_time);
    config.batches = batches.unwrap_or(config.batches);
    Ok(Some((config, format)))
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_value<T: std::str::FromStr>(value: String, option: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{option} has invalid value {value:?}"))
}

fn suite_name(suite: Suite) -> &'static str {
    match suite {
        Suite::Smoke => "smoke",
        Suite::Datapath => "datapath",
    }
}

fn print_help() {
    println!(
        "\
NIC-free ruster-core benchmark foundation

Usage: ruster-bench [OPTIONS]
  --suite smoke|datapath
  --format human|jsonl|both
  --seed U64
  --samples N
  --sample-ms N
  --warmup-ms N
  --batches N[,N...]

Timed regions exclude fixture reset and batch acquisition. Any successful
allocation observed inside a timed region fails the run."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_cli_values_override_suite_defaults_deterministically() {
        let arguments = [
            "--suite",
            "datapath",
            "--samples",
            "3",
            "--batches",
            "1,64",
            "--format",
            "jsonl",
        ]
        .into_iter()
        .map(str::to_owned);
        let (config, format) = parse_args(arguments).unwrap().unwrap();
        assert_eq!(config.suite, Suite::Datapath);
        assert_eq!(config.samples, 3);
        assert_eq!(config.batches, [1, 64]);
        assert_eq!(format, OutputFormat::JsonLines);
    }

    #[test]
    fn option_order_does_not_change_suite_overrides() {
        let arguments = ["--samples", "3", "--suite", "datapath"]
            .into_iter()
            .map(str::to_owned);
        let (config, _) = parse_args(arguments).unwrap().unwrap();
        assert_eq!(config.suite, Suite::Datapath);
        assert_eq!(config.samples, 3);
    }
}
