use anyhow::{anyhow, Context, Result};
use async_std::task::sleep;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fmt, thread};
use tor_linkspec::TransportIdError;
use tracing::{info, warn};

use arti::reload_cfg::ReconfigurableModule;
use arti::{dns, exit, proxy, reload_cfg, ArtiCombinedConfig, ArtiConfig};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{CfgPath, PtTransportName, Reconfigure, TorClientConfigBuilder};
use arti_client::{DormantMode, TorClient, TorClientConfig};
use tor_config::{ConfigurationSources, Listen};
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

use tracing_subscriber::fmt::{Layer, Subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[macro_use]
extern crate lazy_static;

/// OnionVPN control-API version exported over JNI (`controlApiVersionJNI`).
/// Bump when adding/breaking Ext JNI methods.
pub const ONIONVPN_CONTROL_API_VERSION: i32 = 1;

lazy_static! {
    static ref STATE: Mutex<AMExState> = Mutex::new(AMExState::Uninitialized);
    /// Live TorClient handle for set_dormant / reconfigure / bootstrap_status.
    static ref CLIENT: Mutex<Option<TorClient<PreferredRuntime>>> = Mutex::new(None);
    /// Last start params — used to rebuild TorClientConfig for live max_dirtiness.
    static ref RUNTIME_PARAMS: Mutex<Option<RuntimeParams>> = Mutex::new(None);
}

enum AMExState {
    Uninitialized,
    Initialized,
    Starting,
    Running,
    Stopping,
    Stopped,
}

impl fmt::Display for AMExState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AMExState::Initialized => write!(f, "Initialized"),
            AMExState::Running => write!(f, "Running"),
            AMExState::Starting => write!(f, "Starting"),
            AMExState::Stopped => write!(f, "Stopped"),
            AMExState::Stopping => write!(f, "Stopping"),
            AMExState::Uninitialized => write!(f, "Uninitialized"),
        }
    }
}

#[derive(Clone)]
struct RuntimeParams {
    cache_dir: String,
    state_dir: String,
    obfs4_port: u16,
    snowflake_port: u16,
    obfs4proxy_path: Option<String>,
    bridge_lines: Option<String>,
    max_dirtiness_sec: u64,
}

fn start_arti_proxy<F>(
    cache_dir: &str,
    state_dir: &str,
    obfs4_port: u16,
    snowflake_port: u16,
    obfs4proxy_path: Option<&str>,
    bridge_lines: Option<&str>,
    socks_port: u16,
    dns_port: u16,
    log_fn: F,
) -> Result<String>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    _init_log_subscriber(log_fn);
    _configure_and_run_arti_proxy(
        cache_dir,
        state_dir,
        obfs4_port,
        snowflake_port,
        obfs4proxy_path,
        bridge_lines,
        socks_port,
        dns_port,
    );

    Ok("arti-mobile-ex proxy init".to_owned())
}

fn _init_log_subscriber<F>(log_fn: F)
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    if let Ok(mut state) = STATE.lock() {
        if let AMExState::Uninitialized = *state {
            let log_fn = Arc::new(log_fn);
            let log = Layer::new().with_writer(move || CallbackWriter::new(log_fn.clone()));
            Subscriber::builder().finish().with(log).init();

            *state = AMExState::Initialized;
            info!("AMEx: state changed to {}", *state);
        } else {
            info!("AMEx: logging already initialied");
        }
    }
}

fn read_max_dirtiness_sec(state_dir: &str) -> u64 {
    let path = Path::new(state_dir).join("onionvpn_circuit_timing");
    let default = 600u64;
    let Ok(text) = std::fs::read_to_string(&path) else {
        return default;
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("max_dirtiness_sec=") {
            if let Ok(n) = v.trim().parse::<u64>() {
                return n.clamp(60, 7_200);
            }
        }
    }
    default
}

fn write_max_dirtiness_sec(state_dir: &str, secs: u64) {
    let path = Path::new(state_dir).join("onionvpn_circuit_timing");
    let body = format!("max_dirtiness_sec={}\n", secs.clamp(60, 7_200));
    let _ = std::fs::write(path, body);
}

fn build_client_config(params: &RuntimeParams) -> Result<TorClientConfig> {
    let mut client_config_builder =
        TorClientConfigBuilder::from_directories(&params.state_dir, &params.cache_dir);

    let ptn: Result<PtTransportName, TransportIdError> = "snowflake".parse();
    ptn.unwrap_or_else(|err| {
        panic!("err snowflake fuckup {:?}", err);
    });

    if params.obfs4_port > 0 {
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec!["obfs4".parse().unwrap()])
            .proxy_addr(SocketAddr::new("127.0.0.1".parse().unwrap(), 47300));
        client_config_builder.bridges().transports().push(transport);
    }

    if params.snowflake_port > 0 {
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec!["snowflake".parse().unwrap()])
            .proxy_addr(SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                params.snowflake_port,
            ));
        client_config_builder.bridges().transports().push(transport);
    }

    if let Some(o4p) = params.obfs4proxy_path.as_deref() {
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec!["obfs4".parse().unwrap()])
            .path(CfgPath::new(o4p.into()))
            .run_on_startup(true);
        client_config_builder.bridges().transports().push(transport);
    }
    if let Some(l) = params.bridge_lines.as_deref() {
        for bridge_line in l.split('\n') {
            let bridge_line = bridge_line.trim();
            if bridge_line.is_empty() {
                continue;
            }
            client_config_builder
                .bridges()
                .bridges()
                .push(bridge_line.parse().unwrap());
        }
    }

    // MaxCircuitDirtiness analogue — CircuitTimingBuilder::max_dirtiness
    client_config_builder
        .circuit_timing()
        .max_dirtiness(Duration::from_secs(params.max_dirtiness_sec.clamp(60, 7_200)));

    client_config_builder
        .build()
        .map_err(|e| anyhow!("TorClientConfig build failed: {e}"))
}

fn _configure_and_run_arti_proxy(
    cache_dir: &str,
    state_dir: &str,
    obfs4_port: u16,
    snowflake_port: u16,
    obfs4proxy_path: Option<&str>,
    bridge_lines: Option<&str>,
    socks_port: u16,
    dns_port: u16,
) {
    if let Ok(mut state) = STATE.lock() {
        if let AMExState::Initialized | AMExState::Stopped = *state {
            *state = AMExState::Starting;
            info!("AMEx: state changed to {}", *state);
        } else {
            info!(
                "AMEx: _configure_and_run_arti_proxy called from wrong state: {} (expected: Initialized or Stopped)",
                *state
            );
            return;
        }
    } else {
        info!("AMEx: could not lock state, aborting _configure_and_run_arti_proxy()");
        return;
    }

    let runtime = PreferredRuntime::create().expect("Could not create Tor runtime.");
    let config_sources = ConfigurationSources::default();
    let arti_config = ArtiConfig::default();

    let max_dirtiness_sec = read_max_dirtiness_sec(state_dir);
    let params = RuntimeParams {
        cache_dir: cache_dir.to_owned(),
        state_dir: state_dir.to_owned(),
        obfs4_port,
        snowflake_port,
        obfs4proxy_path: obfs4proxy_path.map(|s| s.to_owned()),
        bridge_lines: bridge_lines.map(|s| s.to_owned()),
        max_dirtiness_sec,
    };
    if let Ok(mut g) = RUNTIME_PARAMS.lock() {
        *g = Some(params.clone());
    }

    let client_config = match build_client_config(&params) {
        Ok(c) => c,
        Err(e) => {
            warn!("AMEx: failed to build client config: {e}");
            if let Ok(mut state) = STATE.lock() {
                *state = AMExState::Stopped;
            }
            return;
        }
    };

    info!(
        "AMEx: starting with max_dirtiness_sec={} bridges={}",
        max_dirtiness_sec,
        params.bridge_lines.as_ref().map(|s| s.lines().count()).unwrap_or(0)
    );

    thread::spawn(move || {
        runtime
            .clone()
            .block_on(_run(
                runtime,
                Listen::new_localhost(socks_port),
                Listen::new_localhost(dns_port),
                config_sources,
                arti_config,
                client_config,
            ))
            .expect("Could not start Arti.");
    });
}

/// Shorthand for a boxed and pinned Future.
type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

/// Internal type to represent the Arti application as a `ReconfigurableModule`.
pub(crate) struct Application {
    original_config: ArtiConfig,
}

impl Application {
    pub(crate) fn new(cfg: ArtiConfig) -> Self {
        Self {
            original_config: cfg,
        }
    }
}

impl ReconfigurableModule for Application {
    #[allow(clippy::cognitive_complexity)]
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> Result<()> {
        let original = &self.original_config;
        let config = &new.0;

        if config.proxy() != original.proxy() {
            warn!("Can't (yet) reconfigure proxy settings while arti is running.");
        }
        if config.logging() != original.logging() {
            warn!("Can't (yet) reconfigure logging settings while arti is running.");
        }

        Ok(())
    }
}

async fn _run(
    runtime: PreferredRuntime,
    socks_listen: Listen,
    dns_listen: Listen,
    config_sources: ConfigurationSources,
    arti_config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    if let Ok(state) = STATE.lock() {
        if let AMExState::Starting = *state {
            // no action required here
        } else {
            let e = format!(
                "AMEx: _configure_and_run_arti_proxy called from wrong state: {} (expected: Starting)",
                *state
            );
            return Err(anyhow!(e));
        }
    } else {
        let e = "AMEx: could not lock state, aborting _configure_and_run_arti_proxy()";
        return Err(anyhow!(e));
    }

    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;

    let client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    let client = client_builder.create_unbootstrapped_async().await?;

    // Publish handle for OnionVPN Ext JNI (set_dormant / timing / bootstrap).
    if let Ok(mut g) = CLIENT.lock() {
        *g = Some(client.clone());
    }

    #[allow(unused_mut)]
    let mut reconfigurable_modules: Vec<Arc<dyn reload_cfg::ReconfigurableModule>> = vec![
        Arc::new(client.clone()),
        Arc::new(Application::new(arti_config.clone())),
    ];

    let launched_onion_svc = false;

    let weak_modules = reconfigurable_modules.iter().map(Arc::downgrade).collect();
    reload_cfg::watch_for_config_changes(
        client.runtime(),
        config_sources,
        &arti_config,
        weak_modules,
    )?;

    let rpc_data = None;

    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();
    if !socks_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        let socks_listen = socks_listen.clone();
        proxy.push(Box::pin(async move {
            let res = proxy::run_proxy(runtime, client, socks_listen, rpc_data).await;
            (res, "SOCKS")
        }));
    }

    if !dns_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = dns::run_dns_resolver(runtime, client, dns_listen).await;
            (res, "DNS")
        }));
    }

    if proxy.is_empty() {
        if !launched_onion_svc {
            warn!(
                "No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option."
            );
            clear_client_handle();
            return Ok(());
        } else {
            proxy.push(Box::pin(futures::future::pending()));
        }
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
        r = proxy.fuse()
            => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            client.bootstrap().await?;
            if !socks_listen.is_empty() {
                info!("Sufficiently bootstrapped; proxy now functional.");
            } else {
                info!("Sufficiently bootstrapped.");
            }

            if let Ok(mut state) = STATE.lock(){
                *state = AMExState::Running;
                info!("AMEx: state changed to {}", *state);
            }

            loop {
                sleep(Duration::from_millis(200)).await;
                if let Ok(state) = STATE.lock() {
                    if let AMExState::Stopping = *state {
                        info!("AMEx: Stopping requst detected, stopping proxy");
                        break;
                    }
                }
            }

            futures::future::pending::<Result<()>>().await
        }.fuse()
            => r.context("bootstrap"),
    )?;

    drop(reconfigurable_modules);
    clear_client_handle();

    if let Ok(mut state) = STATE.lock() {
        *state = AMExState::Stopped;
        info!("AMEx: state changed to {}", *state);
    }

    Ok(())
}

fn clear_client_handle() {
    if let Ok(mut g) = CLIENT.lock() {
        *g = None;
    }
}

#[derive(Clone)]
struct CallbackWriter<F> {
    func: Arc<F>,
}

impl<F> CallbackWriter<F>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    pub fn new(callback: Arc<F>) -> Self {
        CallbackWriter { func: callback }
    }
}

impl<F> std::io::Write for CallbackWriter<F>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.func)(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn stop_arti_proxy() {
    if let Ok(mut state) = STATE.lock() {
        if let AMExState::Running = *state {
            *state = AMExState::Stopping;
            info!("AMEx: state changed to {}", *state);
        }
    }
}

/// TorClient::set_dormant — Soft reduces background work; Normal wakes fully.
fn set_arti_dormant(soft: bool) -> Result<()> {
    let guard = CLIENT
        .lock()
        .map_err(|_| anyhow!("CLIENT lock poisoned"))?;
    let client = guard
        .as_ref()
        .ok_or_else(|| anyhow!("Arti client not running"))?;
    let mode = if soft {
        DormantMode::Soft
    } else {
        DormantMode::Normal
    };
    client.set_dormant(mode);
    info!("AMEx: set_dormant({:?})", mode);
    Ok(())
}

/// Live CircuitTimingBuilder::max_dirtiness via TorClient::reconfigure.
fn apply_arti_max_dirtiness(secs: u64) -> Result<()> {
    let secs = secs.clamp(60, 7_200);
    let mut params = RUNTIME_PARAMS
        .lock()
        .map_err(|_| anyhow!("RUNTIME_PARAMS lock poisoned"))?
        .clone()
        .ok_or_else(|| anyhow!("Arti runtime params missing"))?;
    params.max_dirtiness_sec = secs;
    write_max_dirtiness_sec(&params.state_dir, secs);

    let new_config = build_client_config(&params)?;
    let guard = CLIENT
        .lock()
        .map_err(|_| anyhow!("CLIENT lock poisoned"))?;
    let client = guard
        .as_ref()
        .ok_or_else(|| anyhow!("Arti client not running"))?;
    client.reconfigure(&new_config, Reconfigure::WarnOnFailures)?;
    if let Ok(mut g) = RUNTIME_PARAMS.lock() {
        *g = Some(params);
    }
    info!("AMEx: applied max_dirtiness_sec={secs} via reconfigure");
    Ok(())
}

/// BootstrapStatus::as_frac (0.0..=1.0). Returns -1.0 if client not ready.
fn arti_bootstrap_fraction() -> f32 {
    let Ok(guard) = CLIENT.lock() else {
        return -1.0;
    };
    match guard.as_ref() {
        Some(client) => client.bootstrap_status().as_frac(),
        None => -1.0,
    }
}

fn arti_ready_for_traffic() -> bool {
    let Ok(guard) = CLIENT.lock() else {
        return false;
    };
    match guard.as_ref() {
        Some(client) => client.bootstrap_status().ready_for_traffic(),
        None => false,
    }
}

/// Expose the JNI interface for Android
#[cfg(target_os = "android")]
pub mod android;

/// Expose the native interface for iOS
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod apple;
