use crate::policy::Res;
use serde::Serialize;
#[derive(Serialize)]
pub struct Action {
    pub id: &'static str,
    pub description: &'static str,
    pub class: &'static str,
    pub usage: &'static str,
    pub review: bool,
}
macro_rules! item {
    ($id:literal,$d:literal,$c:literal,$u:literal,$r:literal) => {
        Action {
            id: $id,
            description: $d,
            class: $c,
            usage: $u,
            review: $r,
        }
    };
}
static ACTIONS: &[Action] = &[
    item!(
        "status",
        "Show connection and current job.",
        "status",
        "",
        false
    ),
    item!("doctor", "Find what blocks access.", "status", "", false),
    item!("model", "Show device model.", "view", "", false),
    item!("android", "Show Android version.", "view", "", false),
    item!(
        "battery",
        "Show charge, power and temperature.",
        "view",
        "",
        false
    ),
    item!("storage", "Show free space.", "view", "", false),
    item!("memory", "Show memory use.", "view", "", false),
    item!("cpu", "Show current CPU load.", "view", "", false),
    item!("thermal", "Check heat and throttling.", "view", "", false),
    item!("uptime", "Show time since boot.", "view", "", false),
    item!("network", "Show active networks.", "view", "", false),
    item!("wifi", "Show Wi-Fi connection details.", "view", "", false),
    item!("focus", "Show which app has input.", "view", "", false),
    item!("displays", "List available screens.", "view", "", false),
    item!("power", "Show awake and sleep state.", "view", "", false),
    item!("packages", "List installed apps.", "view", "", false),
    item!("processes", "List running processes.", "view", "", false),
    item!(
        "screenshot",
        "Save the main screen to stdout.",
        "view",
        "",
        false
    ),
    item!("logs", "Show recent device logs.", "view", "", false),
    item!("crash-logs", "Show recent app crashes.", "view", "", false),
    item!(
        "jobs",
        "Show who is using this device.",
        "status",
        "",
        false
    ),
    item!(
        "identity",
        "Check saved identity status.",
        "status",
        "",
        false
    ),
    item!("wake", "Wake the screen.", "control", "", false),
    item!(
        "keep-awake",
        "Keep awake while working.",
        "policy",
        "",
        false
    ),
    item!(
        "allow-sleep",
        "Stop readb wake requests.",
        "policy",
        "",
        false
    ),
    item!("home", "Open the home screen.", "control", "", false),
    item!("back", "Go back once.", "control", "", false),
    item!(
        "open-app",
        "Launch an installed app.",
        "control",
        "PACKAGE",
        false
    ),
    item!(
        "stop-app",
        "Stop one selected app.",
        "control",
        "PACKAGE",
        true
    ),
    item!(
        "restart-app",
        "Stop and reopen an app.",
        "recipe",
        "PACKAGE",
        true
    ),
    item!(
        "app-settings",
        "Open an app's settings.",
        "control",
        "PACKAGE",
        false
    ),
    item!(
        "permission-settings",
        "Open readb's permission settings.",
        "control",
        "PACKAGE",
        false
    ),
    item!("tap", "Tap a screen position.", "control", "X Y", false),
    item!(
        "swipe",
        "Swipe between two points.",
        "control",
        "X1 Y1 X2 Y2 [MS]",
        false
    ),
    item!("key", "Send a named key.", "control", "KEY", false),
    item!("type", "Enter one line of text.", "control", "TEXT", false),
    item!(
        "pull",
        "Copy a file from the device.",
        "control",
        "DEVICE_PATH SERVER_PATH",
        false
    ),
    item!(
        "push",
        "Copy a file to the device.",
        "control",
        "SERVER_PATH DEVICE_PATH",
        true
    ),
    item!(
        "install",
        "Install an APK.",
        "control",
        "SERVER_APK_PATH",
        true
    ),
    item!(
        "uninstall",
        "Remove one selected app.",
        "control",
        "PACKAGE",
        true
    ),
    item!(
        "clear-app-data",
        "Delete an app's local data.",
        "control",
        "PACKAGE",
        true
    ),
    item!(
        "clear-logs",
        "Clear device log buffers.",
        "control",
        "",
        true
    ),
    item!("open-url", "Open a web URL.", "control", "HTTPS_URL", false),
    item!(
        "rotate",
        "Set screen rotation.",
        "control",
        "0|1|2|3",
        false
    ),
    item!(
        "reset-rotation",
        "Restore automatic rotation.",
        "control",
        "",
        false
    ),
    item!(
        "stay-powered",
        "Keep awake while plugged in.",
        "control",
        "",
        false
    ),
    item!(
        "reboot",
        "Restart. Manual unlock may be needed.",
        "control",
        "",
        true
    ),
];
pub fn catalog() -> &'static [Action] {
    ACTIONS
}
pub fn find(id: &str) -> Res<&'static Action> {
    ACTIONS
        .iter()
        .find(|a| a.id == id)
        .ok_or("unknown_action: run readb action ls".into())
}
pub(crate) fn package(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 255
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._".contains(&c))
        && v.contains('.')
}
fn count(args: &[String], n: usize) -> Res<()> {
    if args.len() != n {
        return Err("wrong_action_arguments: readb action inspect NAME".into());
    }
    if args.iter().any(|a| a.is_empty() || a.contains('\0')) {
        return Err("empty_or_invalid_action_argument".into());
    }
    Ok(())
}
pub fn build(id: &str, args: &[String], reviewed: bool) -> Res<Vec<String>> {
    let a = find(id)?;
    if a.review && !reviewed {
        return Err(format!(
            "review_required: {}; repeat with --yes after reviewing target and consequences",
            a.description
        ));
    }
    let mut v:Vec<String>=match id{
 "status"|"doctor"|"jobs"|"identity"=>vec![],
 "model"=>vec!["shell","getprop","ro.product.model"],"android"=>vec!["shell","getprop","ro.build.version.release"],
 "battery"=>vec!["shell","dumpsys","battery"],"storage"=>vec!["shell","df","-h"],"memory"=>vec!["shell","cat","/proc/meminfo"],"cpu"=>vec!["shell","cat","/proc/loadavg"],"uptime"=>vec!["shell","cat","/proc/uptime"],
 "thermal"=>vec!["shell","dumpsys","thermalservice"],"network"=>vec!["shell","dumpsys","connectivity"],"wifi"=>vec!["shell","dumpsys","wifi"],"focus"=>vec!["shell","dumpsys","input"],"displays"=>vec!["shell","dumpsys","display"],"power"=>vec!["shell","dumpsys","power"],"packages"=>vec!["shell","pm","list","packages"],"processes"=>vec!["shell","ps","-A"],
 "screenshot"=>vec!["exec-out","screencap","-p"],"logs"=>vec!["logcat","-d"],"crash-logs"=>vec!["logcat","-d","-b","crash"],
 "wake"=>vec!["shell","input","keyevent","KEYCODE_WAKEUP"],"home"=>vec!["shell","input","keyevent","KEYCODE_HOME"],"back"=>vec!["shell","input","keyevent","KEYCODE_BACK"],
 "clear-logs"=>vec!["logcat","-c"],"reset-rotation"=>vec!["shell","wm","user-rotation","free"],"stay-powered"=>vec!["shell","svc","power","stayon","true"],"reboot"=>vec!["reboot"],
 "keep-awake"|"allow-sleep"=>vec!["policy"],
 "restart-app"=>{count(args,1)?;if !package(&args[0]){return Err("invalid_package".into())}return Ok(vec!["recipe".into(),"restart-app".into(),args[0].clone()])},
 "open-app"|"stop-app"|"app-settings"|"permission-settings"|"uninstall"|"clear-app-data"=>{
  count(args,1)?;if !package(&args[0]){return Err("invalid_package".into())}
  return Ok(match id{"open-app"=>vec!["shell".into(),"monkey".into(),"-p".into(),args[0].clone(),"-c".into(),"android.intent.category.LAUNCHER".into(),"1".into()],"stop-app"=>vec!["shell".into(),"am".into(),"force-stop".into(),args[0].clone()],"uninstall"=>vec!["uninstall".into(),args[0].clone()],"clear-app-data"=>vec!["shell".into(),"pm".into(),"clear".into(),args[0].clone()],_=>vec!["shell".into(),"am".into(),"start".into(),"-a".into(),"android.settings.APPLICATION_DETAILS_SETTINGS".into(),"-d".into(),format!("package:{}",args[0])]})
 },
 "tap"|"swipe"=>{if id=="tap"{count(args,2)?;}else if args.len()!=4&&args.len()!=5{return Err("swipe_requires_four_coordinates_and_optional_duration".into())}
            if args.iter().any(|a|a.parse::<u32>().ok().is_none_or(|n|n>100000)){return Err("invalid_coordinate_or_duration".into())}let mut out=vec!["shell".into(),"input".into(),id.into()];out.extend_from_slice(args);return Ok(out)},
 "key"=>{count(args,1)?;let key=args[0].trim_start_matches("KEYCODE_").to_ascii_uppercase();if !["HOME","BACK","ENTER","TAB","ESCAPE","DPAD_UP","DPAD_DOWN","DPAD_LEFT","DPAD_RIGHT","DEL","FORWARD_DEL","SPACE","VOLUME_UP","VOLUME_DOWN","VOLUME_MUTE","WAKEUP","APP_SWITCH"].contains(&key.as_str()){return Err("unsupported_named_key".into())}return Ok(vec!["shell".into(),"input".into(),"keyevent".into(),format!("KEYCODE_{key}")])},
 "type"=>{count(args,1)?;if !args[0].is_ascii()||args[0].chars().any(char::is_control)||args[0].contains("%s"){return Err("type_requires_one_ascii_line_without_literal_percent_s; use a supported input bridge for other text".into())}return Ok(vec!["shell".into(),"input".into(),"text".into(),args[0].replace(' ',"%s")])},
 "open-url"=>{count(args,1)?;if !(args[0].starts_with("https://")||args[0].starts_with("http://"))||args[0].chars().any(|c|c.is_whitespace()||c.is_control()){return Err("http_or_https_url_required".into())}return Ok(vec!["shell".into(),"am".into(),"start".into(),"-a".into(),"android.intent.action.VIEW".into(),"-d".into(),args[0].clone()])},
 "rotate"=>{count(args,1)?;if !["0","1","2","3"].contains(&args[0].as_str()){return Err("rotation_must_be_0_1_2_or_3".into())}return Ok(vec!["shell".into(),"wm".into(),"user-rotation".into(),"lock".into(),args[0].clone()])},
 "pull"|"push"|"install"=>{count(args,if id=="install"{1}else{2})?;if args.iter().any(|v|v.starts_with('-')||v.chars().any(char::is_control)){return Err("invalid_file_argument".into())}let mut out=vec![id.into()];if id=="install"{out.push("-r".into())}out.extend_from_slice(args);return Ok(out)},
 _=>return Err("unsupported_action".into()),
 }.into_iter().map(str::to_string).collect();
    count(args, 0)?;
    v.shrink_to_fit();
    Ok(v)
}
