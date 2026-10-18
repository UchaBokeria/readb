// Static glibc can dlopen host NSS modules with an incompatible loader. The
// Blackwall root group-lookup acceptance test reproduced an abort. Portable
// releases use musl; native dynamically linked GNU builds remain supported.
#[cfg(all(target_os = "linux", target_env = "gnu", target_feature = "crt-static"))]
compile_error!(
    "Static glibc readb builds are unsupported: build x86_64/aarch64-unknown-linux-musl, or native dynamic GNU for host NSS users."
);

pub mod adb_server;
pub mod backend;
pub mod control;
pub mod http;
pub mod notifier;
pub mod policy;
pub mod runner;
pub mod wire;

pub mod schema;

pub mod registry;

pub mod daemon;

pub mod catalog;
pub mod client;

pub mod actions;

pub mod service;

pub mod events;

pub mod setup;
pub mod setup_journal;
pub mod skills;
pub mod web;

pub mod network;

pub mod network_runtime;

pub mod network_install;

pub mod setup_apply;

pub mod setup_files;

pub mod setup_user;

pub mod user_install;

pub mod network_recovery;

pub mod route_events;

pub mod setup_provider;

pub mod setup_activation;

pub mod setup_systemd;

pub mod network_controller;

pub mod network_authority;

pub mod maintenance;

pub mod setup_upgrade;

pub mod setup_upgrade_systemd;

pub mod enrollment_profile;

pub mod enrollment_journal;

pub mod enrollment_ports;

pub mod enrollment_output;
