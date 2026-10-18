use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use readb::{
    client,
    policy::{Owner, Res},
    registry::Registry,
    schema::ServerConfig,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
#[derive(Parser)]
#[command(
    version,
    about = "Remote ADB. One server. Many devices.",
    subcommand_required = true
)]
struct Cli {
    #[arg(long, global = true)]
    context: Option<String>,
    #[arg(
        long,
        global = true,
        conflicts_with = "context",
        help = "Use local coordinator; server only"
    )]
    local: bool,
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    device: Option<String>,
    #[arg(long, global = true)]
    ticket: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    #[command(subcommand, about = "Plan server setup before changing anything")]
    Setup(SetupCmd),
    #[command(
        subcommand,
        about = "Narrow local WireGuard peer helper; never direct client ADB"
    )]
    Network(NetworkCmd),
    #[command(about = "Run the coordinator")]
    Daemon {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(hide = true)]
    Rpc,
    #[command(subcommand, about = "Choose a server")]
    Context(ContextCmd),
    #[command(subcommand, about = "Find and manage devices")]
    Device(DeviceCmd),
    #[command(subcommand, about = "Share views. Claim one controller per device.")]
    Job(JobCmd),
    #[command(about = "Run a structured ADB command; requires a job ticket")]
    Exec {
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        #[arg(required = true, last = true)]
        args: Vec<String>,
    },
    #[command(subcommand, about = "Useful device actions")]
    Action(ActionCmd),
    #[command(subcommand)]
    Service(ServiceCmd),
    #[command(subcommand)]
    Config(ConfigCmd),
    #[command(about = "Check connection and capability state")]
    Doctor,
    #[command(about = "Show coordinator PID and jobs")]
    Ps,
    #[command(subcommand)]
    Dashboard(DashboardCmd),
    #[command(about = "Read coordinator activity; use action run logs for Android logcat")]
    Logs {
        #[arg(short, long)]
        follow: bool,
        #[arg(long)]
        since: Option<f64>,
        #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u16).range(1..=1000))]
        tail: u16,
    },
    #[command(about = "Read action history")]
    History {
        #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
    #[command(subcommand)]
    Skill(SkillCmd),
    #[command(about = "Install server or remote-only client")]
    Install {
        #[arg(long)]
        server: bool,
        #[arg(long)]
        client: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long,conflicts_with_all=["dry_run","recover"],help="Inspect owned install proof without writing or starting services")]
        inspect: bool,
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(
            long,
            help = "Recover only the exact pending install after verifying recorded files"
        )]
        recover: bool,
    },
    #[command(about = "Print shell completion")]
    Completion { shell: clap_complete::Shell },
    #[command(about = "Print version")]
    Version,
}
#[derive(Subcommand)]
enum NetworkCmd {
    #[command(about = "Install root-owned helper files only; never start a service")]
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    InstallRecover,
    Helper {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    Status,
    Restore,
    Enroll {
        #[arg(long)]
        id: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        address: std::net::Ipv4Addr,
    },
    Rm {
        id: String,
    },
    Reconcile,
}
#[derive(Subcommand)]
enum SetupCmd {
    #[command(
        about = "Inspect this server; print JSON plan and blockers, never change files or VPN"
    )]
    Plan(SetupOptions),
    #[command(about = "Verify saved WireGuard and durable boot unit; never start or change VPN")]
    Provider(SetupOptions),
    #[command(
        about = "Install and activate owned server units with durable recovery; never migrate devices implicitly"
    )]
    Apply {
        #[command(flatten)]
        options: SetupOptions,
        #[arg(long)]
        recover: bool,
    },
    #[command(
        about = "Install journaled root policy/helper files only; never activate services or change VPN"
    )]
    Files {
        #[command(flatten)]
        options: SetupOptions,
        #[arg(
            long,
            help = "Reconcile recorded files with the exact original intent before replay; preserves external edits"
        )]
        recover: bool,
    },
}
#[derive(clap::Args)]
struct SetupOptions {
    #[arg(long, help = "Public WireGuard hostname:port")]
    endpoint: String,
    #[arg(long, default_value = "readb0")]
    interface: String,
    #[arg(long, default_value = "10.88.0.1")]
    address: std::net::Ipv4Addr,
    #[arg(long, default_value_t = 24, value_parser=clap::value_parser!(u8).range(8..=30))]
    prefix: u8,
    #[arg(long, default_value_t = 51820, value_parser=clap::value_parser!(u16).range(1..))]
    listen_port: u16,
    #[arg(
        long,
        help = "Inspect an existing interface; never regenerate its keys or peers"
    )]
    reuse_interface: bool,
    #[arg(long, requires_all=["reuse_interface", "range_first", "range_last"], help="Bind installation intent to this non-root passwd user; still read-only")]
    user: Option<String>,
    #[arg(
        long,
        requires = "user",
        help = "User-owned install path within the selected home; default ~/.local/lib/readb"
    )]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        requires = "user",
        help = "First unused IPv4 for readb enrollment"
    )]
    range_first: Option<std::net::Ipv4Addr>,
    #[arg(
        long,
        requires = "user",
        help = "Last unused IPv4 for readb enrollment"
    )]
    range_last: Option<std::net::Ipv4Addr>,
}
#[derive(Subcommand)]
enum ContextCmd {
    Ls,
    Add {
        name: String,
        #[arg(long)]
        ssh: String,
        #[arg(long, default_value = "~/.local/bin/readb")]
        binary: String,
        #[arg(long)]
        state: PathBuf,
    },
    Use {
        name: String,
    },
    Inspect {
        name: Option<String>,
    },
    Rm {
        name: String,
    },
}
#[derive(Subcommand)]
enum DeviceCmd {
    Ls,
    Inspect,
    #[command(about = "Import a private device JSON without restarting other devices")]
    Add {
        #[arg(long)]
        file: PathBuf,
    },
    Config,
    #[command(about = "Pair over the fixed VPN peer; code read privately from stdin")]
    Pair {
        #[arg(long,value_parser=clap::value_parser!(u16).range(1024..))]
        port: u16,
    },
    #[command(about = "Reconnect to the reported secure port, or review first identity")]
    Connect {
        #[arg(long,value_parser=clap::value_parser!(u16).range(1024..))]
        port: Option<u16>,
    },
    #[command(about = "Pause automatic reconnect and keepalive for this device")]
    Disconnect,
    #[command(about = "Pin a freshly reviewed first device identity")]
    Trust {
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        yes: bool,
    },
    #[command(about = "Remove the record; retain keys and private state")]
    Rm {
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Clone, ValueEnum)]
enum Mode {
    View,
    Control,
}
#[derive(Subcommand)]
enum JobCmd {
    Ls,
    Claim {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        origin: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        job: String,
        #[arg(long, value_enum, default_value = "control")]
        mode: Mode,
        #[arg(long, default_value_t = 90)]
        ttl: u64,
        #[arg(long)]
        allow_sleep: bool,
    },
    Inspect,
    Heartbeat,
    Release,
    Cancel,
}
#[derive(Subcommand)]
enum ActionCmd {
    Ls,
    Inspect {
        name: String,
    },
    Run {
        #[arg(long)]
        yes: bool,
        name: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
}
#[derive(Subcommand)]
enum ServiceCmd {
    Install,
    Enable,
    Start,
    Stop,
    Restart,
    Status,
    Uninstall,
}
#[derive(Subcommand)]
enum ConfigCmd {
    Show,
    Validate {
        file: PathBuf,
    },
    Migrate,
    #[command(about = "Recover a pending catalog write offline; stop coordinator first")]
    Recover {
        #[arg(long)]
        file: PathBuf,
    },
}
#[derive(Subcommand)]
enum DashboardCmd {
    Enable {
        #[arg(long, default_value_t = 9870)]
        port: u16,
    },
    KeyLocation,
    Disable,
    Status,
}
#[derive(Subcommand)]
enum SkillCmd {
    Install {
        #[arg(value_parser=["codex","claude","opencode","hermes","all"])]
        tool: String,
    },
    Show,
}
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("readb: {e}");
            std::process::exit(78)
        }
    }
}
fn output(v: &Value) {
    println!("{}", serde_json::to_string(v).unwrap());
}
fn run() -> Res<i32> {
    let c = Cli::parse();
    if let Some(p) = &c.state_dir {
        unsafe {
            std::env::set_var("READB_STATE_DIR", p);
        }
    }
    match &c.command {
        Cmd::Network(cmd) => {
            if !c.local {
                return Err("network_requires_explicit_--local_on_server".into());
            }
            use readb::network::Request;
            if let NetworkCmd::Install { dry_run } = cmd {
                output(&readb::network_install::install_on_server(*dry_run)?);
                return Ok(0);
            }
            if matches!(cmd, NetworkCmd::InstallRecover) {
                output(&readb::network_install::recover_on_server()?);
                return Ok(0);
            }
            use readb::network_runtime::{self, Call};
            if let NetworkCmd::Helper { policy, state } = cmd {
                network_runtime::serve(policy, state)?;
                return Ok(0);
            }
            let call = match cmd {
                NetworkCmd::Status => Call::Status,
                NetworkCmd::Restore => Call::Restore,
                NetworkCmd::Reconcile => Call::Reconcile,
                NetworkCmd::Enroll { id, key, address } => Call::Apply {
                    request: Request::Enroll {
                        id: id.clone(),
                        key: key.clone(),
                        address: *address,
                    },
                },
                NetworkCmd::Rm { id } => Call::Apply {
                    request: Request::Remove { id: id.clone() },
                },
                _ => unreachable!(),
            };
            output(&network_runtime::call(call)?);
            return Ok(0);
        }
        Cmd::Config(ConfigCmd::Recover { file }) => {
            if !c.local {
                return Err("catalog_recovery_requires_--local_on_server".into());
            }
            output(&readb::catalog::recover(&client::state_dir()?, file)?);
            return Ok(0);
        }
        Cmd::Setup(cmd) => {
            let (options, files, recover, provider, apply) = match cmd {
                SetupCmd::Plan(options) => (options, false, false, false, false),
                SetupCmd::Files { options, recover } => (options, true, *recover, false, false),
                SetupCmd::Provider(options) => (options, false, false, true, false),
                SetupCmd::Apply { options, recover } => (options, true, *recover, false, true),
            };
            let SetupOptions {
                endpoint,
                interface,
                address,
                prefix,
                listen_port,
                reuse_interface,
                user,
                install_dir,
                range_first,
                range_last,
            } = options;
            if !c.local {
                return Err(
                    "setup_requires_explicit_--local_on_server; PC clients stay SSH-only".into(),
                );
            }
            if files || provider {
                if unsafe { libc::geteuid() } != 0 {
                    return Err("setup_files_requires_root_on_server".into());
                }
                if user.is_none() || !reuse_interface {
                    return Err("setup_files_requires_user_and_explicit_existing_interface".into());
                }
            }
            let owner = user
                .as_deref()
                .map(readb::setup_apply::Owner::resolve)
                .transpose()?;
            let home = match &owner {
                Some(o) => o.home.clone(),
                None => PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?),
            };
            if !home.is_absolute() {
                return Err("absolute_HOME_required".into());
            }
            let options = readb::setup::Options {
                endpoint: endpoint.clone(),
                interface: interface.clone(),
                address: *address,
                prefix: *prefix,
                listen_port: *listen_port,
                mode: if *reuse_interface {
                    readb::setup::NetworkMode::Reuse
                } else {
                    readb::setup::NetworkMode::Create
                },
            };
            let plan = readb::setup::inspect(options, &home)?;
            let plan = if let Some(owner) = &owner {
                let mut facts = plan.facts;
                facts.storage_writable = owner.can_write_home()?;
                readb::setup::build_plan(plan.options, facts)?
            } else {
                plan
            };
            if (files || provider) && plan.facts.init != "systemd" {
                return Err(
                    "setup_systemd_adapter_required: other init adapters are not implemented"
                        .into(),
                );
            }
            let ready = plan.ready;
            if let Some(owner) = owner {
                if !ready {
                    output(&serde_json::to_value(plan).map_err(|_| "plan_encoding_failed")?);
                    return Ok(78);
                }
                use readb::network::Kernel;
                let mut kernel = readb::network_runtime::LinuxKernel::new()?;
                let policy = readb::network::Policy {
                    schema: 1,
                    uid: owner.uid,
                    interface: plan.options.interface.clone(),
                    server_key: kernel.public_key(&plan.options.interface)?,
                    server_address: plan.options.address,
                    prefix: plan.options.prefix,
                    first: range_first.ok_or("range_first_required")?,
                    last: range_last.ok_or("range_last_required")?,
                };
                let snapshot = kernel.snapshot(&policy)?;
                let binary =
                    std::fs::read("/proc/self/exe").map_err(|_| "executing_binary_unavailable")?;
                let destination = install_dir
                    .clone()
                    .unwrap_or_else(|| owner.home.join(".local/lib/readb"));
                let bound = readb::setup_apply::bind_with_install_dir(
                    plan.options.clone(),
                    owner,
                    policy,
                    snapshot,
                    &binary,
                    destination,
                )?;
                if apply {
                    output(&readb::setup_systemd::apply(&bound, &binary, recover)?);
                } else if provider {
                    let evidence =
                        readb::setup_provider::inspect(&bound.policy, bound.options.listen_port)?;
                    output(
                        &serde_json::json!({"provider":evidence,"files_installed":false,"helper_active":false,"coordinator_active":false,"devices_accepted":false}),
                    );
                } else if files {
                    let result = if recover {
                        readb::setup_files::recover(std::path::Path::new("/"), &bound, &binary)?
                    } else {
                        readb::setup_files::apply(std::path::Path::new("/"), &bound, &binary)?
                    };
                    output(&result);
                } else {
                    output(
                        &serde_json::json!({"preflight":plan,"apply_intent":bound,"applied":false}),
                    );
                }
            } else {
                output(&serde_json::to_value(plan).map_err(|_| "plan_encoding_failed")?);
            }
            return Ok(if ready { 0 } else { 78 });
        }
        Cmd::Version => {
            println!("readb {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Cmd::Completion { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), "readb", &mut std::io::stdout());
            return Ok(0);
        }
        Cmd::Skill(SkillCmd::Show) => {
            print!("{}", readb::skills::SOURCE);
            return Ok(0);
        }
        Cmd::Skill(SkillCmd::Install { tool }) => {
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?);
            output(&readb::skills::install(&home, tool)?);
            return Ok(0);
        }
        Cmd::Context(sub) => return context(sub),
        Cmd::Rpc => {
            if !c.local {
                return Err("rpc_is_server_local_only".into());
            }
            client::rpc(&client::state_dir()?)?;
            return Ok(0);
        }
        Cmd::Daemon { config } => {
            if !c.local {
                return Err("daemon_requires_explicit_--local".into());
            }
            let config =
                ServerConfig::parse(&fs::read(config).map_err(|_| "configuration_unavailable")?)?;
            let r = Arc::new(Registry::new_at(
                config,
                client::state_dir()?,
                match &c.command {
                    Cmd::Daemon { config } => config.clone(),
                    _ => unreachable!(),
                },
            )?);
            let stop = Arc::new(AtomicBool::new(false));
            unsafe {
                libc::signal(
                    libc::SIGTERM,
                    stop_signal as *const () as libc::sighandler_t,
                );
                libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
            }
            let flag = stop.clone();
            thread::spawn(move || {
                while !STOP.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(100));
                }
                flag.store(true, Ordering::SeqCst);
            });
            readb::daemon::serve(r, stop)?;
            return Ok(0);
        }
        Cmd::Install {
            server,
            client: client_mode,
            dry_run,
            inspect,
            prefix,
            recover,
        } => {
            if server == client_mode {
                return Err("choose_--server_or_--client".into());
            }
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?);
            let prefix = prefix
                .clone()
                .unwrap_or_else(|| home.join(".local/share/readb"));
            let p = readb::service::plan(&home, &prefix, *server)?;
            if *inspect {
                output(&readb::service::inspect(&p, &home)?);
                return Ok(0);
            }
            output(&readb::service::install_recover(
                &p, &home, *dry_run, *recover,
            )?);
            return Ok(0);
        }
        Cmd::Service(sub) => {
            if !c.local {
                return Err("service_management_requires_--local_on_server; connect through configured SSH context, never direct device transport".into());
            }
            if matches!(sub, ServiceCmd::Install) {
                return Err("run readb install --server [--prefix PATH]".into());
            }
            let action = match sub {
                ServiceCmd::Enable => "enable",
                ServiceCmd::Start => "start",
                ServiceCmd::Stop => "stop",
                ServiceCmd::Restart => "restart",
                ServiceCmd::Status => "status",
                ServiceCmd::Uninstall => "uninstall",
                _ => unreachable!(),
            };
            output(&readb::service::manage(action)?);
            return Ok(0);
        }
        Cmd::Config(ConfigCmd::Validate { file }) => {
            ServerConfig::parse(&fs::read(file).map_err(|_| "configuration_unavailable")?)?;
            output(&json!({"valid":true,"schema":1}));
            return Ok(0);
        }
        _ => {}
    }
    let context = client::select(c.context.as_deref(), c.local)?;
    let mut req = client::request("status", c.device.as_deref());
    let mut stream = false;
    if let Some(p) = &c.ticket {
        req.ticket = client::read_ticket(p)?;
    }
    match &c.command {
        Cmd::Device(DeviceCmd::Ls) | Cmd::Doctor | Cmd::Job(JobCmd::Ls) => {}
        Cmd::Device(DeviceCmd::Inspect) | Cmd::Job(JobCmd::Inspect) => {
            required_device(&c)?;
        }
        Cmd::Logs {
            follow,
            since,
            tail,
        } => {
            if since.is_some_and(|s| !s.is_finite() || s < 0.) {
                return Err("invalid_since: use nonnegative Unix seconds".into());
            }
            return activity(
                &context,
                c.device.as_deref(),
                *follow,
                *since,
                *tail as usize,
            );
        }
        Cmd::History { limit } => {
            req.action = "history".into();
            req.args = vec![limit.to_string()];
        }
        Cmd::Device(DeviceCmd::Connect { port }) => {
            required_device(&c)?;
            req.action = "connect".into();
            req.args = port.map(|p| p.to_string()).into_iter().collect();
        }
        Cmd::Device(DeviceCmd::Disconnect) => {
            required_device(&c)?;
            req.action = "disconnect".into();
        }
        Cmd::Device(DeviceCmd::Trust { fingerprint, yes }) => {
            required_device(&c)?;
            if !yes {
                return Err("review_required: verify the paired device and displayed fingerprint; pass --yes".into());
            }
            req.action = "trust".into();
            req.args = vec![fingerprint.clone()];
        }
        Cmd::Device(DeviceCmd::Pair { port }) => {
            required_device(&c)?;
            req.action = "exec".into();
            req.args = vec!["pair".into(), port.to_string()];
            req.timeout = 30;
            let code = pairing_code()?;
            return client::call_with_input(&context, &req, true, Some(code)).map(|(code, _)| code);
        }
        Cmd::Device(DeviceCmd::Add { file }) => {
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let mut f = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(file)
                .map_err(|_| "private_import_unavailable")?;
            let m = f.metadata().map_err(|_| "private_import_unavailable")?;
            if !m.is_file()
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0
                || m.len() > 8192
            {
                return Err("private_import_requires_owned_600_file_maximum_8192_bytes".into());
            }
            let mut raw = String::new();
            f.read_to_string(&mut raw)
                .map_err(|_| "private_import_unavailable")?;
            let _: readb::schema::DeviceImport =
                serde_json::from_str(&raw).map_err(|_| "invalid_device_import")?;
            req.action = "device-add".into();
            req.device.clear();
            req.args = vec![raw];
        }
        Cmd::Device(DeviceCmd::Rm { yes }) => {
            required_device(&c)?;
            if !yes {
                return Err(
                    "review_required: removing the device record retains private state; pass --yes"
                        .into(),
                );
            }
            req.action = "device-rm".into();
        }
        Cmd::Ps => req.action = "ps".into(),
        Cmd::Dashboard(sub) => {
            req.action = "dashboard".into();
            req.device.clear();
            req.args = match sub {
                DashboardCmd::Enable { port } => vec!["enable".into(), port.to_string()],
                DashboardCmd::Disable => vec!["disable".into()],
                DashboardCmd::Status => vec!["status".into()],
                DashboardCmd::KeyLocation => vec!["key-location".into()],
            };
        }
        Cmd::Config(ConfigCmd::Show) => req.action = "config".into(),
        Cmd::Job(JobCmd::Claim {
            agent,
            origin,
            session,
            job,
            mode,
            ttl,
            allow_sleep,
        }) => {
            required_device(&c)?;
            req.action = "claim".into();
            req.owner = Some(Owner {
                agent: agent.clone(),
                origin: origin.clone(),
                session: session.clone(),
                job: job.clone(),
                allow_sleep: *allow_sleep,
            });
            req.observe = matches!(mode, Mode::View);
            req.ttl = *ttl;
        }
        Cmd::Job(sub) => {
            required_device(&c)?;
            req.action = match sub {
                JobCmd::Heartbeat => "heartbeat",
                JobCmd::Release => "release",
                JobCmd::Cancel => "cancel",
                _ => return Err("invalid_job_action".into()),
            }
            .into()
        }
        Cmd::Action(ActionCmd::Run { name, args, yes }) => {
            required_device(&c)?;
            let action = readb::actions::find(name)?;
            let argv = readb::actions::build(name, args, *yes)?;
            if action.class == "status" {
            } else if action.class == "policy" {
                req.action = "keepalive".into();
                req.args = vec![if name == "keep-awake" { "on" } else { "off" }.into()];
            } else if action.class == "recipe" {
                for step in ["stop-app", "open-app"] {
                    let mut operation = client::request("exec", Some(&req.device));
                    operation.ticket = req.ticket.clone();
                    operation.args = readb::actions::build(step, args, true)?;
                    let (code, _) = client::call(&context, &operation, true)?;
                    if code != 0 {
                        return Ok(code);
                    }
                }
                return Ok(0);
            } else {
                req.action = "exec".into();
                req.args = argv;
                stream = true;
            }
        }
        Cmd::Exec { timeout, args } => {
            required_device(&c)?;
            req.action = "exec".into();
            req.timeout = *timeout;
            req.args = args.clone();
            stream = true;
        }
        _ => return Err("command_not_available_in_development_build; see docs/status.md".into()),
    }
    let (code, data) = client::call(&context, &req, stream)?;
    if code != 0 {
        return Ok(code);
    }
    if !stream {
        let mut v: Value =
            serde_json::from_slice(&data).map_err(|_| "invalid_coordinator_reply")?;
        if req.action == "claim"
            && let Err(e) = client::store_ticket(&mut v, &req.device)
        {
            let mut release = client::request("release", Some(&req.device));
            release.ticket = v["token"].as_str().unwrap_or("").into();
            let _ = client::call(&context, &release, false);
            return Err(e);
        }
        if c.quiet && matches!(&c.command, Cmd::Device(DeviceCmd::Ls)) {
            if let Some(devices) = v["devices"].as_array() {
                for d in devices {
                    if let Some(id) = d["id"].as_str() {
                        println!("{id}")
                    }
                }
            }
        } else {
            output(&v)
        }
    }
    Ok(0)
}
fn required_device(c: &Cli) -> Res<()> {
    if c.device
        .as_ref()
        .is_none_or(|d| !readb::schema::valid_id(d))
    {
        return Err("select_device: pass --device ID; run readb device ls".into());
    }
    Ok(())
}
fn context(sub: &ContextCmd) -> Res<i32> {
    let mut c = client::contexts()?;
    match sub {
        ContextCmd::Ls => output(&serde_json::to_value(&c).unwrap()),
        ContextCmd::Add {
            name,
            ssh,
            binary,
            state,
        } => {
            if !readb::schema::valid_id(name)
                || ssh.is_empty()
                || ssh.starts_with('-')
                || ssh.chars().any(|c| c.is_whitespace() || c.is_control())
                || !state.is_absolute()
                || binary.is_empty()
                || binary.chars().any(char::is_control)
            {
                return Err("invalid_context".into());
            }
            if c.contexts.contains_key(name) {
                return Err("context_exists: inspect or remove it explicitly".into());
            }
            c.contexts.insert(
                name.clone(),
                client::Context {
                    ssh: Some(ssh.clone()),
                    binary: binary.clone(),
                    state: state.clone(),
                },
            );
            if c.current.is_none() {
                c.current = Some(name.clone())
            }
            client::save(&c)?;
            output(&json!({"added":name}));
        }
        ContextCmd::Use { name } => {
            if !c.contexts.contains_key(name) {
                return Err("unknown_context".into());
            }
            c.current = Some(name.clone());
            client::save(&c)?;
            output(&json!({"current":name}));
        }
        ContextCmd::Inspect { name } => {
            let n = name.as_ref().or(c.current.as_ref()).ok_or("no_context")?;
            output(&serde_json::to_value(c.contexts.get(n).ok_or("unknown_context")?).unwrap());
        }
        ContextCmd::Rm { name } => {
            if c.contexts.remove(name).is_none() {
                return Err("unknown_context".into());
            }
            if c.current.as_ref() == Some(name) {
                c.current = None;
            }
            client::save(&c)?;
            output(&json!({"removed":name}));
        }
    }
    Ok(0)
}

fn activity(
    context: &client::Context,
    device: Option<&str>,
    follow: bool,
    since: Option<f64>,
    tail: usize,
) -> Res<i32> {
    use std::collections::VecDeque;
    use std::io::Write;
    unsafe {
        libc::signal(
            libc::SIGTERM,
            stop_signal as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
    }
    let mut seen: VecDeque<String> = VecDeque::new();
    let mut first = true;
    loop {
        let mut req = client::request("history", device);
        req.args = vec![if first { tail } else { 1000 }.to_string()];
        let (code, data) = client::call(context, &req, false)?;
        if code != 0 {
            return Ok(code);
        }
        let v: Value = serde_json::from_slice(&data).map_err(|_| "invalid_history_reply")?;
        for row in v["events"].as_array().ok_or("invalid_history_reply")? {
            let line = serde_json::to_string(row).map_err(|_| "invalid_history_event")?;
            if since.is_none_or(|s| row["epoch"].as_f64().is_some_and(|e| e >= s))
                && !seen.contains(&line)
            {
                println!("{line}");
                seen.push_back(line);
                if seen.len() > 2000 {
                    seen.pop_front();
                }
            }
        }
        std::io::stdout().flush().map_err(|_| "stdout_closed")?;
        if !follow || STOP.load(Ordering::SeqCst) {
            return Ok(0);
        }
        first = false;
        for _ in 0..10 {
            if STOP.load(Ordering::SeqCst) {
                return Ok(0);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn pairing_code() -> Res<Vec<u8>> {
    use std::io::{IsTerminal, Write};
    struct Echo(Option<libc::termios>, Vec<(i32, libc::sigaction)>);
    impl Drop for Echo {
        fn drop(&mut self) {
            if let Some(t) = &self.0 {
                unsafe {
                    libc::tcsetattr(0, libc::TCSAFLUSH, t);
                }
            }
            for (signal, action) in &self.1 {
                unsafe {
                    libc::sigaction(*signal, action, std::ptr::null_mut());
                }
            }
        }
    }
    let mut saved = Echo(None, Vec::new());
    if std::io::stdin().is_terminal() {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(0, term.as_mut_ptr()) } != 0 {
            return Err("cannot_disable_pairing_code_echo".into());
        }
        let old = unsafe { term.assume_init() };
        let mut hidden = old;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &hidden) } != 0 {
            return Err("cannot_disable_pairing_code_echo".into());
        }
        saved.0 = Some(old);
        for signal in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGTSTP,
            libc::SIGQUIT,
            libc::SIGHUP,
        ] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = stop_signal as *const () as libc::sighandler_t;
            let mut previous = std::mem::MaybeUninit::uninit();
            if unsafe { libc::sigaction(signal, &action, previous.as_mut_ptr()) } != 0 {
                return Err("pairing_signal_setup_failed".into());
            }
            saved.1.push((signal, unsafe { previous.assume_init() }));
        }
        eprint!("Pairing code: ");
        let _ = std::io::stderr().flush();
    }
    let mut code = Vec::new();
    while code.len() < 16 {
        if STOP.load(Ordering::SeqCst) {
            return Err("pairing_cancelled".into());
        }
        let mut p = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut p, 1, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err("pairing_code_unavailable".into());
        }
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
        if n == 0 || byte == b'\n' {
            break;
        }
        if n < 0 {
            return Err("pairing_code_unavailable".into());
        }
        code.push(byte);
    }
    if saved.0.is_some() {
        eprintln!();
    }
    if code.last() == Some(&b'\r') {
        code.pop();
    }
    if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
        return Err("pairing_code_must_have_six_digits".into());
    }
    code.push(b'\n');
    Ok(code)
}
