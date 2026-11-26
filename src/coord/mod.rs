//! Distributed scanning: a controller that plans and allocates work, clients
//! that scan blocks, and the coverage model that makes resume exact.
//!
//! # Modes
//!
//! ```text
//! zorpinvader --rate 20000 -p 80,443        standalone: scheduler + engine in one process
//! zorpinvader --server 8000 -p 80,443       controller: schedules, never transmits
//! zorpinvader --client https://zi.example   client: claims blocks, transmits, reports
//! ```
//!
//! The controller is plain HTTP/1.1, so it can sit behind any reverse proxy or
//! tunnel (`cloudflared`, Caddy, nginx) and clients reach it over `http://` or
//! `https://` without the binary needing its own TLS stack.
//!
//! # Coverage, not a cursor
//!
//! The old resume model was a single index into a shuffled global space: it
//! could only say "we stopped here", and it could only continue in one order.
//! Coverage is now a *set of addresses* ([`set4::RangeSet4`]):
//!
//! * Work is divided into CIDR-aligned blocks ([`plan::Plan`]).
//! * A completed block adds its interval to the covered set.
//! * Resume is `targets - covered` — exact, and independent of block size or
//!   client count.
//! * Serialised as a minimal CIDR decomposition, so the state file grows with
//!   the number of *gaps* in coverage, not with the number of addresses. A
//!   thousand contiguous /24s cost one interval.
//!
//! Blocks are leased, not assigned: an unresponsive client loses its block after
//! the lease expires and the block goes back to the pool resuming at its last
//! reported position.
//!
//! # Modules
//!
//! * [`set4`] — address-set algebra and CIDR decomposition.
//! * [`plan`] — targets → aligned blocks, deterministic block ordering.
//! * [`scheduler`] — leases, coverage accounting, state file, results de-dupe.
//! * [`protocol`] — the JSON wire format.
//! * [`http`] — a minimal HTTP/1.1 server.
//! * [`server`] — the controller: HTTP handlers around a [`scheduler::Scheduler`].
//! * [`client`] — the client loop: join → claim → scan → report.
//! * [`local`] — standalone mode: the same scheduler, in-process.
//! * [`targets`] — collect the target set from a [`Zorp`] config.

pub mod client;
pub mod http;
pub mod local;
pub mod plan;
pub mod protocol;
pub mod results;
pub mod scheduler;
pub mod server;
pub mod set4;
pub mod targets;

pub use plan::Plan;
pub use scheduler::{Claim, JobSpec, Scheduler};
pub use set4::RangeSet4;
