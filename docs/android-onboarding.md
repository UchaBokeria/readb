# Connect without a file

Implementation in progress. Not live acceptance.

Default setup is a verified HTTPS server address and one-use setup code.
Keep file import under advanced setup for existing administrators.

Native Java owns HTTPS and private enrollment storage. WebView gets only public
progress. No setup code, recovery credential, envelope or profile is returned to
JavaScript. Keep the local WebView network policy unchanged.

Use the frozen `/onboard/v1/claim`, `/resume`, `/ack` contract in
`docs/enrollment-first-user.md`. Persist request and random recovery credential
before the first request. Same request resumes after interruption; never create a
second recipient to recover an uncertain reply. ACK only after durable storage;
mark ready only after verifying and durably saving the final receipt.

Transport rejects HTTP, URL credentials/query/fragment/path, redirects, wrong
content type, compressed or oversized responses. Use ordinary platform TLS and
hostname validation. Bound connect/read/total time and allow explicit cancel.
Never echo server error bodies or credentials in diagnostics. Server errors are
mapped to brief known messages. Cancel stops polling; it does not delete peers.

Tests first: address validation, actual local TLS response/redirect/size handling,
cancel and error behavior; then storage integration and app lifecycle. Real gate:
new Pixel install state -> address/code -> encrypted profile -> Android VPN
consent -> Blackwall handshake/report -> secure pairing/pin -> real ADB. Keep
legacy routes until this succeeds. A mock server or APK build is not acceptance.
