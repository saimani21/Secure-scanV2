# Core v0.1 limitations

- Input is limited to local repository directories. There is no cloning, archive upload,
  or remote authentication.
- The trusted baseline contains exactly three Python demonstration rules. It is not full
  Python coverage, multi-language coverage, or a replacement for maintained Semgrep
  policies.
- Micro-benchmark precision and recall do not predict accuracy on real repositories.
- The Docker daemon, host administrator, selected digest-pinned image, kernel, and
  container runtime remain trusted.
- Authentication, authorization, multi-tenant isolation, distributed workers, SCA,
  validated secret detection, and AI triage are outside Core v0.1.
- Deployment backup, retention, artifact access control, high availability, and disaster
  recovery remain operator responsibilities.
- A valid scanner diagnostic creates partial analysis; it does not fabricate a clean
  result.
- PostgreSQL is required for the production-oriented durable and concurrency paths.
