# Public Streamlit deployment source

Verified in the Streamlit Manage app panel on 2026-10-11:

- App: https://secure-sight-cs.streamlit.app/
- Repository: https://github.com/Himanshu6611/Secure-Sight
- Branch: `codex/production-readiness`
- Entrypoint: `streamlit_app/main.py`

`Himanshu6611/SecureSight` (without the hyphen) is a different repository.
Pushing its `origin` does not update this public app. The deployment worktree
can share that other repository's local Git configuration, so verify the push
destination explicitly before publishing. Never overwrite the deployment
entrypoint with the other repository's version: their UI implementations differ.

The image origin panel exposes the loaded model SHA-256 and decision threshold
under its technical breakdown. Verify those against `models/image_origin/evaluation.json`
after deployment, using a fresh scan rather than a previous result left in a tab.
