'use strict';
const $ = id => document.getElementById(id);
function command(op) {
  if (window.Readb) window.Readb.command(JSON.stringify({op}));
  else $('message').textContent = 'Design preview. Device controls are available in the Android app.';
}
window.updateReadb = state => {
  $('live').textContent = state.vpn_active ? 'Private VPN active' : state.report_enabled ? 'Connecting' : 'Stopped';
  $('live').classList.toggle('active', !!state.vpn_active);
  document.querySelector('.signal').classList.toggle('active', !!state.vpn_active);
  $('vpn').textContent = state.vpn_message || 'Not started';
  $('report').textContent = state.report_message || 'Not started';
  const age = Date.now() - state.last_report_epoch;
  $('last').textContent = !state.last_report_epoch ? 'No report yet' : age < 0 ? 'Device clock changed' : `${Math.floor(age / 1000)} seconds ago`;
  $('enrolled').textContent = state.enrolled ? 'Encrypted profile saved' : 'Profile missing';
  $('notifications').textContent = state.notifications ? 'Allowed' : 'Not allowed. Connection status may be less visible.';
  $('secure').textContent = state.secure_settings ? 'Secure-settings access granted. Protected unlock still depends on Android.' : 'Extra secure-settings access is not granted. Wireless debugging may need manual activation after reboot.';
  $('start').disabled = !state.enrolled || !!state.report_enabled;
  $('stop').disabled = !state.report_enabled && !state.vpn_enabled;
  if (state.message) $('message').textContent = state.message;
};
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => command(button.dataset.action)));
if (window.Readb) { command('status'); setInterval(() => command('status'), 3000); }
else window.updateReadb({enrolled:false, report_message:'Not started', vpn_message:'Not started'});
