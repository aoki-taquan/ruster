use anyhow::Result;
use ruster_config::RouterConfig;
use ruster_dataplane::Dataplane;
use ruster_observe::Counters;

fn main() -> Result<()> {
    let config = RouterConfig {
        hostname: "ruster-lab".to_string(),
    };
    ruster_control::validate(&config)?;

    let dataplane = Dataplane::new();
    dataplane.start();

    let mut counters = Counters::default();
    counters.inc_drop();

    println!("ruster bootstrap ok: hostname={}", config.hostname);
    Ok(())
}
