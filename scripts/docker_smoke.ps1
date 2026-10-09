param(
    [string]$Image = 'securesight:phase18-review'
)

$ErrorActionPreference = 'Stop'
$name = "securesight-smoke-$PID"
$started = $false

try {
    & docker run --detach --name $name --network none --read-only `
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 `
        --memory 2g --cpus 2 --pids-limit 128 --cap-drop ALL `
        --security-opt no-new-privileges:true `
        -e APP_ENV=testing -e TRUSTED_HOSTS=localhost,127.0.0.1 `
        -e SEO_INDEXING_ENABLED=false $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Docker failed to start the smoke container.' }
    $started = $true

    $security = & docker inspect --format '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}' $name
    if ($LASTEXITCODE -ne 0 -or $security -ne '10001:10001|true|none') {
        throw "Unexpected container security settings: $security"
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $running = & docker inspect --format '{{.State.Running}}' $name 2>$null
        if ($LASTEXITCODE -ne 0 -or $running -ne 'true') { break }

        $probe = & docker exec $name python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:5000/api/v1/ready', timeout=3).status)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $probe -eq '200') {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 3
    }
    if (-not $ready) {
        & docker logs --tail 60 $name
        throw 'Readiness did not return HTTP 200 within 120 seconds.'
    }

    $frontend = & docker exec $name python -c "import urllib.request; base='http://localhost:5000'; page=urllib.request.urlopen(base+'/',timeout=3).read().decode(); css=urllib.request.urlopen(base+'/static/ui/style.css',timeout=3).read().decode(); js=urllib.request.urlopen(base+'/static/ui/app.js',timeout=3).read(); assert 'id=' in page and 'api-docs' not in page and '.app-shell' in css and len(js)>100000; print('frontend-ok')" 2>$null
    if ($LASTEXITCODE -ne 0 -or $frontend -ne 'frontend-ok') { throw 'Built React frontend assets did not pass container smoke checks.' }

    & docker stop --time 30 $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Docker failed to stop the smoke container.' }
    $started = $false
    $exitCode = & docker inspect --format '{{.State.ExitCode}}' $name
    if ($LASTEXITCODE -ne 0 -or $exitCode -ne '0') {
        throw "Container did not exit cleanly after SIGTERM (exit code $exitCode)."
    }

    Write-Output 'PASS: isolated readiness, React frontend assets, non-root/read-only/network settings, graceful SIGTERM.'
}
finally {
    if ($started) { & docker rm --force $name | Out-Null }
    else { & docker rm $name 2>$null | Out-Null }
}
