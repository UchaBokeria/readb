//! Android bridge. No Linux subprocesses or network I/O. Enrollment input is never echoed.
use readb_protocol::{Companion, Observed};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    ValidateProfile {
        profile: readb_protocol::Profile,
    },
    Create {
        epoch: String,
        now: u64,
    },
    Close {
        handle: u64,
    },
    Port {
        handle: u64,
        now: u64,
        port: Option<u16>,
    },
    Network {
        handle: u64,
        now: u64,
    },
    Poll {
        handle: u64,
        now: u64,
        battery: i16,
        observed: Observed,
    },
    Complete {
        handle: u64,
        sequence: u64,
        now: u64,
        success: bool,
    },
}
#[derive(Default)]
pub struct Bridge {
    next: u64,
    reporters: BTreeMap<u64, Companion>,
}
impl Bridge {
    pub fn call(&mut self, input: &str) -> String {
        let result = (|| {
            if input.len() > 8192 {
                return Err("request_too_large".into());
            }
            let request = serde_json::from_str(input).map_err(|_| "invalid_request")?;
            self.dispatch(request)
        })();
        match result {
            Ok(v) => v.to_string(),
            Err(e) => json!({"ok":false,"error":e}).to_string(),
        }
    }
    fn reporter(&mut self, handle: u64) -> Result<&mut Companion, String> {
        self.reporters
            .get_mut(&handle)
            .ok_or_else(|| "unknown_reporter".into())
    }
    fn dispatch(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::ValidateProfile { profile } => {
                profile.validate()?;
                Ok(
                    json!({"ok":true,"device_id":profile.device_id,"server_peer":profile.server_peer,"report_path":profile.report_path()}),
                )
            }
            Request::Create { epoch, now } => {
                if self.reporters.len() >= 8 {
                    return Err("reporter_limit".into());
                }
                let c = Companion::new(epoch, now)?;
                let handle = self
                    .next
                    .checked_add(1)
                    .ok_or("reporter_handles_exhausted")?;
                self.next = handle;
                self.reporters.insert(handle, c);
                Ok(json!({"ok":true,"handle":handle,"next_due":now}))
            }
            Request::Close { handle } => {
                self.reporters.remove(&handle).ok_or("unknown_reporter")?;
                Ok(json!({"ok":true}))
            }
            Request::Port { handle, now, port } => {
                let c = self.reporter(handle)?;
                c.port_changed(now, port)?;
                Ok(json!({"ok":true,"next_due":c.next_due()}))
            }
            Request::Network { handle, now } => {
                let c = self.reporter(handle)?;
                c.network_changed(now);
                Ok(json!({"ok":true,"next_due":c.next_due()}))
            }
            Request::Poll {
                handle,
                now,
                battery,
                observed,
            } => {
                let c = self.reporter(handle)?;
                let report = c.poll(now, battery, observed)?;
                Ok(json!({"ok":true,"report":report,"next_due":c.next_due()}))
            }
            Request::Complete {
                handle,
                sequence,
                now,
                success,
            } => {
                let c = self.reporter(handle)?;
                c.complete(sequence, now, success)?;
                Ok(json!({"ok":true,"next_due":c.next_due()}))
            }
        }
    }
}
static BRIDGE: OnceLock<Mutex<Bridge>> = OnceLock::new();
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_readb_companion_NativeBridge_call<'local>(
    mut unowned: jni::EnvUnowned<'local>,
    _class: jni::objects::JClass<'local>,
    input: jni::objects::JString<'local>,
) -> jni::objects::JString<'local> {
    unowned
        .with_env(|env| -> Result<_, jni::errors::Error> {
            // JNI limits allocation before converting untrusted Java strings.
            let response = if input.is_null() {
                json!({"ok":false,"error":"invalid_request"}).to_string()
            } else if env
                .call_method(&input, jni::jni_str!("length"), jni::jni_sig!("()I"), &[])?
                .i()?
                > 8192
            {
                json!({"ok":false,"error":"request_too_large"}).to_string()
            } else {
                match BRIDGE.get_or_init(|| Mutex::new(Bridge::default())).lock() {
                    Ok(mut bridge) => bridge.call(&input.try_to_string(env)?),
                    Err(_) => json!({"ok":false,"error":"bridge_unavailable"}).to_string(),
                }
            };
            jni::objects::JString::from_str(env, response)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
