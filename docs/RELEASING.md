# Releasing JSScope

JSScope ships three kinds of artifacts:

| Artifact | Where | Workflow |
|---|---|---|
| Wheel + sdist | GitHub Release assets | `.github/workflows/release.yml` |
| Container image | `ghcr.io/venu-exe/jsscope` | `.github/workflows/release.yml` |
| PyPI package | `pypi.org/project/jsscope` | `.github/workflows/publish-pypi.yml` |

## Cutting a release

1. Bump the version in both places (they must match):

   - `pyproject.toml` → `[project] version`
   - `jsscope.py` → `VERSION`

2. Run the tests and build locally:

   ```bash
   python3 -m pytest -q
   python3 -m build
   ```

3. Commit the bump:

   ```bash
   git add pyproject.toml jsscope.py
   git commit -m "release: vX.Y.Z"
   git push origin master
   ```

4. Create and push an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "JSScope X.Y.Z"
   git push origin vX.Y.Z
   ```

   Pushing the tag triggers the release workflow, which:
   - builds `jsscope-X.Y.Z-py3-none-any.whl` and the sdist,
   - installs the wheel in a clean venv and runs `jsscope --version`,
   - creates/updates the GitHub Release and attaches both files,
   - builds and pushes the container image with `X.Y.Z`, `X.Y`, and `latest` tags.

   On the first container publish, set the GHCR package visibility to **public**
   under **Packages → jsscope → Package settings** if you want anonymous pulls
   (`docker pull ghcr.io/venu-exe/jsscope`).

5. Optionally edit the GitHub Release description with highlights.

6. If PyPI publishing is enabled (see below), publishing the release also
   uploads the same wheel and sdist to PyPI.

## Enabling PyPI publishing

Publishing uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
so no API token is stored in the repository.

1. Sign in to PyPI and add a **pending trusted publisher** at
   <https://pypi.org/manage/account/publishing/>:

   | Field | Value |
   |---|---|
   | PyPI project name | `jsscope` |
   | Owner | `Venu-exe` |
   | Repository | `JSScope` |
   | Workflow name | `publish-pypi.yml` |
   | Environment | `pypi` |

2. In GitHub, create an environment named `pypi` under
   **Settings → Environments** (no secrets required).

3. Add a repository variable **Settings → Secrets and variables → Actions →
   Variables**:

   ```
   PUBLISH_TO_PYPI = true
   ```

   The workflow is skipped while the variable is absent or `false`, so normal
   releases stay green before PyPI is configured.

4. Publish a release (or run the `publish-pypi` workflow manually). The first
   successful upload claims the `jsscope` name on PyPI.

## Verifying a release

```bash
gh release view vX.Y.Z
docker run --rm ghcr.io/venu-exe/jsscope --version
pip install jsscope            # only after PyPI publishing is enabled
```
