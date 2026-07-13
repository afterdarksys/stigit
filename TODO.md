# StigIt Roadmap and Security TODO

This document tracks the work required to evolve StigIt from a scheduled local
compliance scanner into a securely managed endpoint compliance platform.

## Current State

StigIt currently provides:

- A CLI and macOS management application.
- A `launchd` scheduler that installs a root LaunchDaemon or per-user LaunchAgent.
- Scheduled hourly, daily, or weekly scans.
- Local scanning, reporting, waivers, backups, and controlled remediation.
- Fleet report publication through a shared directory.
- Fleet aggregation and stale-report detection.

The current scheduler is not a remotely managed endpoint daemon. It periodically
executes `stigit-cli scan`; it does not expose or consume an authenticated StigIt
management protocol. The Fleet view reads report files and cannot securely send
commands, policies, rule updates, or remediation requests to endpoints.

Until the secure agent and management service exist, the supported deployment
model should continue to use the organization's MDM as the command-and-control
layer. StigIt should handle local assessment, evidence, and remediation while MDM
handles installation, configuration, credentials, updates, and job execution.

## Security Principles

- [ ] Do not expose an inbound listener on endpoints unless a documented use case
      cannot be served by outbound polling.
- [ ] Use an outbound, mutually authenticated connection from each endpoint.
- [ ] Never accept arbitrary shell commands from the management service.
- [ ] Keep networking and policy processing unprivileged.
- [ ] Keep the privileged helper small and limited to allowlisted operations.
- [ ] Make commands, policies, reports, and rule bundles cryptographically verifiable.
- [ ] Fail closed when identity, authorization, signature, freshness, or policy
      validation cannot be established.
- [ ] Preserve evidence of who authorized a change, what ran, and what changed.
- [ ] Treat MDM, code signing, and organizational authorization as part of the trust
      boundary rather than claiming StigIt independently certifies compliance.

## Phase 1: Harden the Existing Scheduled Scanner

### Scheduler correctness

- [ ] Add unit tests for generated LaunchDaemon and LaunchAgent property lists.
- [ ] Validate generated property lists with `plutil` in tests and release checks.
- [ ] Report actual `launchctl` service state rather than only checking whether the
      plist exists.
- [ ] Add a health command that reports the last start, last completion, exit code,
      last successful report upload, and active policy version.
- [ ] Prevent overlapping scans with a process or filesystem lock.
- [ ] Add per-rule and whole-scan execution timeouts.
- [ ] Terminate child processes reliably when a timeout occurs.
- [ ] Add configurable resource limits for CPU, memory, and output size.
- [ ] Adopt current `launchctl bootstrap`, `bootout`, and `kickstart` lifecycle
      operations with explicit domain selection.
- [ ] Verify that installed job files have secure ownership and permissions.
- [ ] Verify that configuration, waiver, rule, and executable paths are absolute and
      cannot be replaced through unsafe symlinks.
- [ ] Detect when the configured CLI executable has moved or been replaced.
- [ ] Define safe upgrade and uninstall behavior for active scheduled jobs.

### Reliability and observability

- [ ] Replace the single unbounded log file with structured, rotated logs.
- [ ] Ensure logs do not contain secrets, tokens, or sensitive command output.
- [ ] Add scan correlation IDs to logs and reports.
- [ ] Add an encrypted local queue for reports that cannot be delivered.
- [ ] Retry failed uploads with exponential backoff and randomized jitter.
- [ ] Set a maximum queue size and documented retention behavior.
- [ ] Distinguish scan failure, upload failure, policy failure, and agent failure.
- [ ] Add a heartbeat independent of compliance scan completion.
- [ ] Make stale-agent detection use server receipt time as well as endpoint time.
- [ ] Detect and report significant endpoint clock drift.

## Phase 2: Establish Strong Endpoint Identity

- [ ] Generate a stable StigIt device UUID that is not derived solely from hostname.
- [ ] Bind enrollment records to available hardware identifiers without treating
      mutable identifiers as sufficient authentication.
- [ ] Design MDM bootstrap enrollment using a one-time, short-lived token.
- [ ] Issue a unique client certificate to every enrolled endpoint.
- [ ] Store endpoint private keys in macOS Keychain using the strongest practical
      hardware-backed protection.
- [ ] Never deploy one reusable fleet-wide client secret.
- [ ] Add certificate expiry monitoring and automated rotation.
- [ ] Add server-side device revocation and quarantine.
- [ ] Define secure reenrollment and device replacement workflows.
- [ ] Record enrollment source, actor, time, MDM identity, agent version, and device
      identity in the management audit log.
- [ ] Add tests for duplicate enrollment, expired tokens, revoked certificates,
      identity mismatch, and rotation failure.

## Phase 3: Build the Secure Agent Transport

- [ ] Implement an outbound HTTPS client in an unprivileged StigIt agent.
- [ ] Require TLS server validation and reject invalid or unexpected trust chains.
- [ ] Add mutual TLS using the endpoint's unique client certificate.
- [ ] Define an explicit, versioned wire protocol.
- [ ] Include request IDs, device IDs, timestamps, sequence numbers, and nonces.
- [ ] Reject expired, duplicated, replayed, or out-of-order security-sensitive
      messages.
- [ ] Define bounded request and response sizes.
- [ ] Add connection, request, and idle timeouts.
- [ ] Support enterprise HTTP proxy configuration without weakening TLS validation.
- [ ] Document certificate pinning and enterprise CA tradeoffs before selecting one.
- [ ] Add protocol compatibility negotiation for agent upgrades.
- [ ] Add integration tests with valid, expired, revoked, and untrusted certificates.
- [ ] Add tests for replay, clock skew, malformed payloads, oversized payloads,
      interrupted uploads, and server unavailability.

## Phase 4: Make Compliance Evidence Verifiable

- [ ] Define a canonical byte representation for signed scan reports.
- [ ] Sign reports using the endpoint identity key.
- [ ] Include device UUID, endpoint certificate identity, agent version, rule-bundle
      version, policy version, sequence number, scan start, and scan completion.
- [ ] Record the server receipt time separately from endpoint-generated timestamps.
- [ ] Reject signatures from unknown, expired, or revoked endpoint identities.
- [ ] Reject reports with stale or duplicate sequence numbers.
- [ ] Preserve the original signed report as immutable evidence.
- [ ] Store later annotations, waivers, and workflow state separately from original
      evidence.
- [ ] Add optional hardware-backed attestation where target Mac hardware and
      organizational policy support it.
- [ ] Define evidence retention, deletion, legal hold, and export requirements.
- [ ] Add integrity verification to fleet imports retained for offline deployments.

## Phase 5: Replace Shared-Drop Fleet Collection

- [ ] Build a management API that accepts authenticated report submissions.
- [ ] Store endpoints by stable device UUID rather than hostname.
- [ ] Treat hostname, serial number, and hardware model as attributes, not identity.
- [ ] Prevent one endpoint from reading or modifying another endpoint's records.
- [ ] Store reports append-only instead of overwriting the last hostname file.
- [ ] Retain report history and policy/rule versions used for every scan.
- [ ] Detect duplicate hostnames and unexpected hardware identity changes.
- [ ] Add server-side validation before a report enters compliance calculations.
- [ ] Make malformed or unverifiable reports visible as errors rather than silently
      skipping them.
- [ ] Add pagination and bounded queries for large fleets.
- [ ] Add fleet health states for enrolled, healthy, stale, offline, revoked,
      quarantined, policy-error, and scan-error endpoints.
- [ ] Keep the shared-directory workflow as an explicitly labeled offline mode if it
      remains useful.
- [ ] For offline mode, add report signatures, replay detection, restrictive ACL
      guidance, and collision-resistant filenames based on device UUID.

## Phase 6: Signed Policy and Rule Distribution

- [ ] Define a versioned endpoint policy model.
- [ ] Include enabled profiles, rule selection, severity gates, scan schedule,
      reporting configuration, waiver sources, and remediation permissions.
- [ ] Sign every policy and rule bundle with a dedicated organizational signing key.
- [ ] Pin or provision trusted policy-signing public keys through MDM.
- [ ] Reject unsigned, expired, downgraded, or incorrectly targeted policies.
- [ ] Add monotonically increasing policy versions and rollback authorization.
- [ ] Verify macOS applicability before activating a rule bundle.
- [ ] Preserve the last known-good policy and rule bundle.
- [ ] Make policy activation atomic.
- [ ] Report policy validation and activation failures to the management service.
- [ ] Add staged rollout rings, canary endpoints, pause, and rollback.
- [ ] Record who created, reviewed, approved, published, and rolled back each policy.
- [ ] Add independent rule-by-rule validation against authoritative benchmark
      versions for each supported macOS release.

## Phase 7: Safe Remote Command Delivery

- [ ] Use endpoint polling for commands rather than an inbound endpoint listener.
- [ ] Define an allowlisted command vocabulary such as `scan`, `install-policy`,
      `collect-diagnostics`, and `remediate-rule-ids`.
- [ ] Do not include a generic shell or script execution command.
- [ ] Sign command envelopes independently from transport security.
- [ ] Include command ID, target device UUID, issuer, approval reference, creation
      time, expiry, policy version, and idempotency key.
- [ ] Reject commands for another endpoint or commands outside their validity window.
- [ ] Persist command receipt and execution state across agent restarts.
- [ ] Return acknowledged, running, succeeded, failed, expired, rejected, and
      cancelled states.
- [ ] Make command execution idempotent where possible.
- [ ] Define safe cancellation semantics.
- [ ] Bound command queue depth and execution duration.
- [ ] Add tests for replay, wrong target, missing approval, expiry, duplicate delivery,
      agent restart, cancellation, and partial failure.

## Phase 8: Privileged Helper and Local Authorization

- [ ] Split the endpoint component into an unprivileged network agent and a minimal
      privileged helper.
- [ ] Use authenticated local IPC/XPC between the components.
- [ ] Validate the calling application's code signature and designated requirement.
- [ ] Expose typed privileged operations rather than accepting shell strings.
- [ ] Maintain an explicit allowlist of files, services, preference domains, and
      commands the helper may modify.
- [ ] Validate every path against traversal, symlink, and race attacks immediately
      before privileged use.
- [ ] Drop privileges for operations that do not require root.
- [ ] Preserve console-user execution context for user-scoped rules.
- [ ] Fail closed if a required console user cannot be established safely.
- [ ] Add local rate limiting and command concurrency controls.
- [ ] Record privileged actions in a tamper-evident local audit trail.
- [ ] Threat-model local unprivileged attackers attempting to impersonate the agent.
- [ ] Add tests that prove untrusted local processes cannot invoke privileged work.

## Phase 9: Controlled Remote Remediation

- [ ] Require a named approver, change ticket, reason, scope, and expiry for remote
      remediation.
- [ ] Support separation of duties between policy authors and remediation approvers.
- [ ] Permit remediation only for explicit rule IDs already present in an approved
      and active policy bundle.
- [ ] Refuse remediation of unknown, errored, inapplicable, or waived rules.
- [ ] Never convert rule remediation into arbitrary server-provided shell text.
- [ ] Create and verify a pre-remediation backup when required by policy.
- [ ] Record before-state evidence for each target rule.
- [ ] Stop on the first unsafe or unexpected failure unless policy explicitly defines
      independent operations.
- [ ] Rescan remediated rules and record after-state evidence.
- [ ] Return per-rule results rather than one combined success value.
- [ ] Define automatic rollback eligibility and require explicit approval for
      destructive rollback.
- [ ] Block or separately authorize controls requiring Recovery Mode, reboot, user
      logout, or loss of network access.
- [ ] Add maintenance windows and fleet concurrency limits.
- [ ] Add canary remediation and automatic rollout pause on elevated failure rates.

## Phase 10: Management Service and Console

### Authentication and authorization

- [ ] Integrate organizational SSO using an approved identity provider.
- [ ] Require strong administrator authentication and support phishing-resistant MFA.
- [ ] Implement role-based access for report viewers, auditors, policy authors,
      waiver approvers, remediation approvers, operators, and platform administrators.
- [ ] Enforce authorization on the server for every API operation.
- [ ] Support least-privilege API service accounts with scoped, expiring credentials.
- [ ] Add session expiry, revocation, and administrator access review workflows.

### Audit and governance

- [ ] Create an append-only administrator audit log.
- [ ] Record actor, action, target, before/after state, reason, ticket, request ID,
      timestamp, source, and result.
- [ ] Make audit exports independently verifiable.
- [ ] Prevent administrators from silently altering original endpoint evidence.
- [ ] Add waiver approval, expiry, renewal, and revocation workflows.
- [ ] Add policy review and dual-approval workflows where required.
- [ ] Define retention and privacy controls for endpoint and user-related data.

### Fleet operations

- [ ] Display enrollment, certificate, agent, policy, scan, upload, and remediation
      health separately.
- [ ] Show the exact policy and rule-bundle version active on each endpoint.
- [ ] Add endpoint groups, tags, saved filters, and scoped policy assignment.
- [ ] Add alerting for stale agents, invalid evidence, policy drift, certificate
      expiry, scan errors, and high-severity findings.
- [ ] Add export and SIEM integration with stable schemas and delivery status.
- [ ] Add command approval, rollout progress, cancellation, and per-endpoint results.
- [ ] Clearly distinguish compliant, noncompliant, waived, unknown, evaluation-error,
      stale, and unverifiable states.

## Phase 11: Secure Updates and Supply Chain

- [ ] Sign and notarize the application, CLI, agent, and privileged helper.
- [ ] Establish reproducible or independently verifiable release builds.
- [ ] Generate SBOMs and provenance attestations for releases.
- [ ] Pin dependencies and automate vulnerability review.
- [ ] Sign update manifests and release artifacts.
- [ ] Verify signatures before installing updates.
- [ ] Support staged deployment, rollback, and minimum-version enforcement.
- [ ] Prevent downgrade to known-vulnerable agent or policy versions.
- [ ] Define emergency certificate, signing-key, and release revocation procedures.
- [ ] Test upgrades while scans, queued reports, commands, and remediation are active.
- [ ] Document MDM packaging, deployment, update, and removal procedures.

## Phase 12: Security Validation and Compliance Readiness

- [ ] Create a formal threat model covering the endpoint, local IPC, transport,
      management service, administrator console, update path, and rule supply chain.
- [ ] Perform independent source review and penetration testing.
- [ ] Test hostile endpoints submitting forged, malformed, oversized, or replayed
      evidence.
- [ ] Test a compromised user account attempting to invoke privileged operations.
- [ ] Test a compromised administrator account against RBAC and approval boundaries.
- [ ] Test management-service outage and endpoint offline operation.
- [ ] Test certificate authority, signing-key, and identity-provider failure scenarios.
- [ ] Run real-device validation for every supported macOS major version.
- [ ] Validate deployment through representative MDM platforms.
- [ ] Validate FileVault, Secure Token, Bootstrap Token, smart-card, accessibility,
      and multi-user edge cases.
- [ ] Create documented incident response and forensic collection procedures.
- [ ] Define recovery time, recovery point, backup, and disaster-recovery objectives.
- [ ] Publish an explicit security model and supported deployment architectures.
- [ ] Avoid marketing language that implies certification or guaranteed compliance.

## Recommended Delivery Order

1. Harden and test the existing scheduler.
2. Add stable device identity and MDM-driven enrollment.
3. Implement outbound mutual-TLS report submission.
4. Add signed reports, replay protection, and immutable evidence storage.
5. Add heartbeat, offline queueing, and fleet health monitoring.
6. Add signed policy and rule distribution.
7. Split privileged execution into a minimal authenticated helper.
8. Add signed, allowlisted command polling.
9. Add controlled remote remediation with approval and rollback safeguards.
10. Complete centralized RBAC, audit, update, and operational controls.

## Definition of a Securely Managed StigIt Endpoint

An endpoint should not be described as securely managed by StigIt until all of the
following are true:

- [ ] It has a unique, revocable cryptographic identity.
- [ ] It communicates through authenticated, encrypted outbound transport.
- [ ] Its reports are signed, fresh, replay-protected, and retained immutably.
- [ ] Its active policy and rule bundle are signed, versioned, and attributable.
- [ ] It accepts only signed, scoped, expiring, allowlisted commands.
- [ ] Privileged operations are isolated behind authenticated local IPC.
- [ ] Remote remediation requires explicit authorization and produces before/after
      evidence.
- [ ] Administrators are authenticated, authorized, and fully audited.
- [ ] The agent can recover safely from outages, interrupted updates, and partial
      command execution.
- [ ] The complete deployment has passed independent security and real-device MDM
      validation.
