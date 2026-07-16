# iAccess Obsidian Pages

Public delivery repository for the internal iAccess Obsidian Database.

This repository is intentionally public because GitHub Pages on GitHub Free
requires a public repository. It must contain only:

- the content-free login shell;
- public Auth0 SPA identifiers;
- encrypted manifest and encrypted binary blobs;
- the GitHub Pages deployment workflow.

Never copy a plaintext export here. In particular, the directories `notes/`,
`api/`, and `assets/vault/` are forbidden. Passwords, tokens, Auth0 secrets,
Netlify secrets, and the AES content key must never be committed.

The repository is populated only by the reviewed secure publisher in the
private `JeremyDays/iAccess-Obsidian` generator repository. Until Auth0 and the
key service are configured and the first encrypted publish succeeds, GitHub
Pages remains intentionally disabled.
