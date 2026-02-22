use anyhow::Result;
use ruster_dataplane::Dataplane;
use ruster_observe::Counters;

fn main() -> Result<()> {
    let config = ruster_config::load_from_file("router.toml.example")?;
    ruster_control::validate(&config)?;

    let dataplane = Dataplane::new();
    dataplane.start();

    let mut counters = Counters::default();
    counters.inc_drop();

    println!("ruster bootstrap ok: hostname={}", config.meta.hostname);
    Ok(())
}
