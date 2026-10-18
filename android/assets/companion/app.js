'use strict';
const $ = id => document.getElementById(id);
let selectedPage = 'connection';
let accessShown = false;
function command(op, fields = {}) {
  if (op !== 'status') { $('notice').hidden = true; $('message').textContent = ''; }
  if (window.Readb) window.Readb.command(JSON.stringify({op, ...fields}));
  else { $('notice').hidden = false; $('message').textContent = 'Device controls are available in the Android app.'; }
}
window.readbNavigate = page => {
  if (!['connection', 'setup', 'settings'].includes(page)) return;
  selectedPage = page;
  document.querySelectorAll('.page').forEach(panel => { panel.hidden = panel.id !== `page-${page}`; });
  document.querySelectorAll('[data-page]').forEach(button => {
    const active = button.dataset.page === page;
    button.classList.toggle('selected', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  });
  window.scrollTo(0, 0);
};
window.updateReadb = state => {
  const running = !!(state.report_enabled || state.vpn_enabled);
  const tunnel = !!state.vpn_active;
  $('live').textContent = !state.enrolled ? 'Setup needed' : tunnel ? 'Tunnel active' : running ? 'Starting' : 'Stopped';
  $('live').classList.toggle('active', tunnel);
  document.querySelector('.signal').classList.toggle('active', tunnel);
  $('connection-title').textContent = !state.enrolled ? 'Connect this device' : tunnel ? 'Private tunnel active' : running ? 'Starting your link' : 'Ready when you are';
  $('connection-copy').textContent = !state.enrolled ? 'Connect to your readb server with its address and a setup code.' : tunnel ? 'The tunnel is up. Check secure ADB below for device access.' : running ? 'Check the status below if the connection does not start.' : 'Your encrypted setup is saved. Start the link to reach your server.';
  $('hero-primary').hidden = !!state.enrolled;
  $('link-actions').hidden = !state.enrolled && !running;
  $('start').hidden = !state.enrolled;
  $('hero-primary').disabled = !state.enrolled && running;
  $('setup-progress').hidden = !state.setup_message;
  $('setup-progress').textContent = state.setup_message || '';
  $('setup-connect').disabled = !!state.setup_active || !!state.enrolled;
  $('setup-server').disabled = !!state.setup_active || !!state.enrolled;
  $('setup-code').disabled = !!state.setup_active || !!state.enrolled;
  $('setup-resume').hidden = !state.setup_saved || !!state.enrolled || !!state.setup_active;
  $('setup-cancel').hidden = !state.setup_active;
  if (state.enrolled || state.setup_active) $('setup-code').value = '';
  $('vpn').textContent = state.vpn_message || 'Not started';
  $('report').textContent = state.wireless_debugging === false ? 'Wireless debugging is off' : state.report_message || 'Not started';
  $('debug-warning').hidden = state.wireless_debugging !== false;
  $('live').classList.toggle('attention', state.wireless_debugging === false && !!state.enrolled);
  if (state.wireless_debugging === false && state.enrolled) $('live').textContent = 'Needs attention';
  const portAge = Date.now() - Number(state.port_observed_epoch || 0);
  const validPort = Number.isInteger(state.remote_port) && state.remote_port >= 1024 && state.remote_port <= 65535;
  const freshPort = validPort && Number(state.port_observed_epoch) > 0 && portAge >= 0 && portAge <= 45000 && state.wireless_debugging !== false;
  $('remote-port').textContent = freshPort ? String(state.remote_port) : 'Not discovered';
  $('remote-port-age').textContent = freshPort ? `Observed ${Math.floor(portAge / 1000)} seconds ago. This is the connection port, not the pairing port.` : state.wireless_debugging === false ? 'Enable wireless debugging to report the port.' : 'Waiting for a current secure ADB port.';
  const age = Date.now() - state.last_report_epoch;
  $('last').textContent = !state.last_report_epoch ? 'No report yet' : age < 0 ? 'Device clock changed' : age < 60000 ? `${Math.floor(age / 1000)} seconds ago` : `${Math.floor(age / 60000)} minutes ago`;
  $('enrolled').textContent = state.enrolled ? 'Encrypted setup saved' : state.setup_saved ? 'Setup saved — ready to resume' : 'Not connected yet';
  $('notifications').textContent = state.notifications ? 'Allowed' : 'Not allowed';
  $('notification-action').textContent = 'Notification settings';
  $('notification-action').dataset.action = 'notifications_settings';
  $('debug-state').textContent = state.wireless_debugging === true ? 'Enabled' : state.wireless_debugging === false ? 'Not enabled' : 'Open settings to check.';
  $('secure').textContent = state.secure_settings ? 'Extra settings access is granted. Protected unlocking still depends on Android.' : 'Extra settings access is not granted. You may need to enable wireless debugging again after reboot.';
  $('start').disabled = !state.enrolled || running;
  $('setup-start').disabled = !state.enrolled || running;
  $('stop').disabled = !running;
  $('vpn-approval-state').textContent = state.vpn_authorized ? 'Approved for readb' : 'Not approved. Tap Allow readb VPN.';
  $('settings-vpn-state').textContent = state.vpn_authorized ? 'Approved. WireGuard is built in.' : 'Not approved. No separate WireGuard app is needed.';
  $('setup-vpn-approval').textContent = state.vpn_authorized ? 'Review readb VPN access' : 'Allow readb VPN';
  $('access-notifications').textContent = state.notifications ? 'Allowed' : 'Not allowed';
  $('access-vpn').textContent = state.vpn_authorized ? 'Approved for readb' : 'Needs Android approval';
  $('access-debug').textContent = state.wireless_debugging === true ? 'Enabled' : state.wireless_debugging === false ? 'Off — open Settings to enable' : 'Open Settings to check';
  if (state.permission_setup_required === true && !accessShown) showAccess();
  if (state.message) { $('notice').hidden = false; $('message').textContent = state.message; }
};
$('hero-primary').addEventListener('click', () => window.readbNavigate('setup'));
$('connect-form').addEventListener('submit', event => {event.preventDefault();const code=$('setup-code').value;command('setup_connect',{server:$('setup-server').value,code});$('setup-code').value='';});
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => command(button.dataset.action)));
document.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => window.readbNavigate(button.dataset.page)));
function showAccess() {
  accessShown = true;
  if (!$('access-dialog').open) $('access-dialog').showModal();
}
function finishAccess() {
  accessShown = true;
  $('access-dialog').close();
  command('finish_access');
}
$('review-access').addEventListener('click', showAccess);
$('finish-access').addEventListener('click', finishAccess);
$('close-access').addEventListener('click', finishAccess);
$('access-dialog').addEventListener('cancel', event => { event.preventDefault(); finishAccess(); });
$('dismiss-message').addEventListener('click', () => { $('notice').hidden = true; $('message').textContent = ''; });
if (window.Readb) { command('status'); setInterval(() => { if (!document.hidden) command('status'); }, 3000); }
else window.updateReadb({enrolled:false, report_message:'Not started', vpn_message:'Not started'});
