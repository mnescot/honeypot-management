- REMOTE HONEYPOT NODES

- Provide ability to manage a collection of remote nodes that are onboarded for management to the central application the running an onboarding script on the remote node
- Remote nodes will be running some variant of Linux operating system; generalize onboarding script and remote management communication for compatibility with generic Linux
- Management of remote nodes integrated into current management interface
- Remote nodes only need to allow outbound HTTPS access over port 443 to communicate with central application
- The central management application can deploy honeypot instances including Beelzebub LLM Honeypot instances to remote nodes after onboarding
- The tpot attack map will integrate information on honeypots deployed to remote nodes
- Periodic health checks on remote nodes and indicators of remote node health status
