# Repository instructions for coding agents

## Verifying `gofmt` on a Windows checkout

CI's `lint` job runs `gofmt -l .` and fails the build if it lists any file
(`.github/workflows/ci.yml`). This repository's git config has
`core.autocrlf=true`, so on a Windows checkout the working tree has CRLF line
endings. `gofmt` normalizes on LF, so a plain `gofmt -l .` (or `gofmt -d`) run
directly against the working tree reports nearly every tracked `.go` file as
unformatted, which is a **false positive** caused by line endings, not a real
formatting defect in the LF-normalized git blob.

Before trusting a local `gofmt` result on Windows, normalize line endings
first, for example:

```powershell
# Check one file against what's actually committed (LF-normalized):
git show HEAD:path/to/file.go > $env:TEMP\file.go
gofmt -l $env:TEMP\file.go   # empty output = clean

# Check every file changed vs main:
$files = git diff --name-only main -- '*.go'
$tmp = New-Item -ItemType Directory -Path "$env:TEMP\gofmtcheck" -Force
foreach ($f in $files) {
  $norm = (Get-Content -Raw $f) -replace "`r`n", "`n"
  [IO.File]::WriteAllText((Join-Path $tmp.FullName ($f -replace '[\\/]', '_')), $norm)
}
gofmt -l $tmp.FullName   # empty output = every changed file is clean
```

Do not conclude a checkout is "all unformatted" from a raw `gofmt -l .` run on
Windows, and do not skip the check just because it looks noisy: normalize
first, then re-run.

## Copilot Code Review can take a few minutes to appear

After opening or updating a pull request, a Copilot Code Review does not
always attach to the PR (or show up in `requested_reviewers` /
`reviewRequests`) immediately. Re-check with `gh pr view <number> --json
reviews,latestReviews,reviewRequests,comments` (or wait and re-check) before
concluding that Copilot Code Review is unavailable, disabled, or blocked at
the org level. An empty result on the first check is not proof of a block.
