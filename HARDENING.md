<!-- markdownlint-disable -->

# Hardening Report: psf--black/26.3.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **psf--black/26.3.1** was hardened automatically. 10 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): `${{ github.event.pull_request.number }}` is directly interpolated into a `grep` shell command in a run block. An attacker who controls the PR number (or a malicious PR title/number) could inject shell metacharacters. Offending line: `grep -Pz "\((\n\s*)?#${{ github.event.pull_request.number }}(\n\s*)?\)" CHANGES.md`

Locations:

- `.github/workflows/changelog.yml:23`

### script-injection (severity: high)

Rule (a): Multiple `${{ matrix.* }}` expressions are directly interpolated into run blocks. Most critically, `${{ matrix.baseline-setup-cmd }}` and `${{ matrix.target-setup-cmd }}` are executed directly as shell commands (arbitrary code execution if matrix values are attacker-controlled). Other matrix values (`${{ matrix.baseline-analysis }}`, `${{ matrix.target-analysis }}`, `${{ matrix.style }}`, `${{ matrix.mode }}`) are also interpolated into run blocks without quoting or env-var indirection.

Locations:

- `.github/workflows/diff_shades.yml:75`
- `.github/workflows/diff_shades.yml:80`
- `.github/workflows/diff_shades.yml:108`
- `.github/workflows/diff_shades.yml:113`
- `.github/workflows/diff_shades.yml:133`
- `.github/workflows/diff_shades.yml:148`
- `.github/workflows/diff_shades.yml:178`
- `.github/workflows/diff_shades.yml:192`
- `.github/workflows/diff_shades.yml:200`
- `.github/workflows/diff_shades.yml:213`

### script-injection (severity: high)

Rule (a): `${{ matrix.python-version }}` is directly interpolated into a shell command: `tox -e ci-py$(echo ${{ matrix.python-version }} | tr -d '.') -- -v --color=yes`. Any expression inside `${{ }}` is substituted before the shell sees the string, enabling injection.

Locations:

- `.github/workflows/test.yml:68`

### script-injection (severity: high)

Rule (a): `${{ matrix.asset_name }}` and `${{ matrix.pathsep }}` are directly interpolated into run block shell commands: `python -m PyInstaller -F --name ${{ matrix.asset_name }} --add-data 'src/blib2to3${{ matrix.pathsep }}blib2to3' ...` and `./dist/${{ matrix.asset_name }} --version`.

Locations:

- `.github/workflows/publish_binaries.yml:55`
- `.github/workflows/publish_binaries.yml:59`
- `.github/workflows/publish_binaries.yml:60`

### script-injection (severity: high)

Rule (b): Env vars sourced from workflow-controllable contexts are used unquoted in shell commands. `$sha` (from `${{ github.event.workflow_run.head_sha }}`) is unquoted in `gh pr list --search $sha`; `$pr` (from `steps.pr.outputs.pr`) and `$run_id` (from `${{ github.event.workflow_run.id }}`) are unquoted in `python scripts/diff_shades_gha_helper.py comment-details $pr $run_id`. Unquoted expansions allow shell metacharacter injection.

Locations:

- `.github/workflows/diff_shades_comment.yml:40`
- `.github/workflows/diff_shades_comment.yml:48`

### script-injection (severity: high)

Rule (b): `$python_ver` (set from `${{ matrix.python-version }}`) is used unquoted in `tox -e fuzz --result-json $python_ver`. An unquoted shell variable expansion allows metacharacter injection if the matrix value contains special characters.

Locations:

- `.github/workflows/fuzz.yml:37`

### script-injection (severity: high)

Rule (b): `$USER` (set from `${{ github.event.release.author.login }}`) is used unquoted in `gh pr create ... -a $USER`. A release author login containing shell metacharacters could cause injection.

Locations:

- `.github/workflows/post_release.yml:55`

### github-env-injection (severity: high)

The `platform` env var (set from `${{ matrix.platform }}`) is written to `$GITHUB_OUTPUT` without sanitization: `echo "platform=${platform//\//-}" >> $GITHUB_OUTPUT`. A newline in the matrix value could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `.github/workflows/docker.yml:44`

### github-env-injection (severity: high)

The `sha` env var (set from `${{ github.event.workflow_run.head_sha }}`) is written to `$GITHUB_OUTPUT` without sanitization: `echo pr=$(gh pr list --search $sha --json number --jq ".[0].number") >> "$GITHUB_OUTPUT"`. A newline in the SHA value could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `.github/workflows/diff_shades_comment.yml:40`

### github-env-injection (severity: high)

The `REPO` env var (set from `${{ github.repository }}`) is written to `$GITHUB_OUTPUT` without sanitization: `echo "ISSUE=$( gh issue list ... -R $REPO )" >> $GITHUB_OUTPUT`. A newline in the repository name could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `.github/workflows/fuzz.yml:60`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 10 security findings across 7 workflow files:

1. changelog.yml: Moved `${{ github.event.pull_request.number }}` into env var PR_NUMBER, referenced as ${PR_NUMBER} in shell.

2. diff_shades.yml: Moved all matrix values (baseline-setup-cmd, target-setup-cmd, baseline-analysis, target-analysis, style, mode) into env blocks and referenced as quoted shell variables. Setup commands use `eval "$VAR"` since they are intentionally shell commands.

3. test.yml: Moved `${{ matrix.python-version }}` into env var PYTHON_VERSION, referenced as "$PYTHON_VERSION" in shell.

4. publish_binaries.yml: Moved `${{ matrix.asset_name }}` and `${{ matrix.pathsep }}` into env vars ASSET_NAME and PATHSEP, referenced as quoted shell variables.

5. diff_shades_comment.yml: Fixed script injection (quoted $sha, $pr, $run_id) and github-env-injection (sanitized sha with printf/tr before writing to GITHUB_OUTPUT).

6. fuzz.yml: Fixed script injection (quoted $python_ver), fixed github-env-injection (sanitized REPO with printf/tr before writing to GITHUB_OUTPUT), and quoted $REPO and $ISSUE in all gh commands.

7. post_release.yml: Quoted $USER in the gh pr create command.

8. docker.yml: Fixed github-env-injection by sanitizing the platform value with printf/tr before writing to GITHUB_OUTPUT.

