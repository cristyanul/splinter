document.addEventListener('DOMContentLoaded', () => {
    fetchConfig();
    setInterval(fetchStatus, 2000);
    setInterval(fetchRadar, 2000);
    fetchRadar();
    setInterval(fetchThreatLog, 5000);
    fetchThreatLog();
    setInterval(fetchJamLog, 5000);
    fetchJamLog();
    document.getElementById('btn-log-csv').addEventListener('click', downloadLogCsv);
    document.getElementById('btn-safe').addEventListener('click', async (e) => {
        const b = e.target;
        await fetch('/api/safe', { method: 'POST' });
        const orig = b.textContent;
        b.textContent = 'Learning ~3 min…';
        setTimeout(() => { b.textContent = orig; }, 4000);
    });

    document.getElementById('config-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            ble_enabled: document.getElementById('ble_enabled').checked,
            ieee154_enabled: document.getElementById('ieee154_enabled').checked,
            wifi_enabled: document.getElementById('wifi_enabled').checked,
            profiles_enabled: document.getElementById('profiles_enabled').checked,
            swarm_enabled: document.getElementById('swarm_enabled').checked,
            thread_enabled: document.getElementById('thread_enabled').checked,
            awdl_enabled: document.getElementById('awdl_enabled').checked,
            jam_detect_enabled: document.getElementById('jam_detect_enabled').checked,
            ieee154_respond: document.getElementById('ieee154_respond').checked,
            ble_adv_ms: parseInt(document.getElementById('ble_adv_ms').value),
            ble_name_prob: parseInt(document.getElementById('ble_name_prob').value),
            ble_mfg_prob: parseInt(document.getElementById('ble_mfg_prob').value),
            ble_refresh_ms: parseInt(document.getElementById('ble_refresh_ms').value),
            ieee154_chan_mask: parseInt(document.getElementById('ieee154_chan_mask').value),
            ieee154_beacon_ms: parseInt(document.getElementById('ieee154_beacon_ms').value),
            wifi_interval_ms: parseInt(document.getElementById('wifi_interval_ms').value),
            softap_ssid: document.getElementById('softap_ssid').value,
            softap_pass: document.getElementById('softap_pass').value
        };
        const btn = document.querySelector('.btn.primary');
        const origText = btn.innerText;
        btn.innerText = 'Saving...';
        
        try {
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                btn.innerText = 'Saved!';
                setTimeout(() => btn.innerText = origText, 2000);
            }
        } catch (err) {
            alert('Failed to save config');
            btn.innerText = origText;
        }
    });

    document.getElementById('btn-reboot').addEventListener('click', async () => {
        if (confirm("Reboot the device? The UI will go offline.")) {
            await fetch('/api/reboot', {method: 'POST'});
            document.getElementById('conn-status').className = 'status-badge offline';
            document.getElementById('conn-status').innerText = 'Rebooting...';
        }
    });

    document.getElementById('btn-ota').addEventListener('click', () => {
        const file = document.getElementById('fw-file').files[0];
        const status = document.getElementById('ota-status');
        if (!file) {
            status.innerText = 'Pick a .bin file first.';
            return;
        }
        if (!confirm('Flash ' + file.name + ' and reboot into it?')) return;
        const btn = document.getElementById('btn-ota');
        btn.disabled = true;

        // XMLHttpRequest (not fetch) so we get real upload-progress events.
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/ota');
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 100);
                status.innerText = 'Uploading... ' + pct + '% (' + (e.loaded / 1024).toFixed(0) + ' KB)';
            }
        };
        xhr.onload = () => {
            status.innerText = xhr.responseText || 'Done.';
            btn.disabled = false;
        };
        xhr.onerror = () => {
            // On success the device reboots and aborts the request mid-response,
            // which surfaces here as a network error — that's the expected path.
            status.innerText = 'Upload finished; device is rebooting into new firmware.';
            btn.disabled = false;
        };
        status.innerText = 'Uploading ' + file.name + ' (' + (file.size / 1024).toFixed(0) + ' KB)...';
        xhr.send(file);
    });
});

async function fetchConfig() {
    try {
        const res = await fetch('/api/config');
        const cfg = await res.json();
        document.getElementById('ble_enabled').checked = cfg.ble_enabled;
        document.getElementById('ieee154_enabled').checked = cfg.ieee154_enabled;
        document.getElementById('wifi_enabled').checked = cfg.wifi_enabled;
        document.getElementById('profiles_enabled').checked = cfg.profiles_enabled;
        document.getElementById('swarm_enabled').checked = cfg.swarm_enabled;
        document.getElementById('thread_enabled').checked = cfg.thread_enabled;
        document.getElementById('awdl_enabled').checked = cfg.awdl_enabled;
        document.getElementById('ieee154_respond').checked = cfg.ieee154_respond;
        document.getElementById('jam_detect_enabled').checked = cfg.jam_detect_enabled;

        document.getElementById('ble_adv_ms').value = cfg.ble_adv_ms;
        document.getElementById('ble_name_prob').value = cfg.ble_name_prob;
        document.getElementById('ble_mfg_prob').value = cfg.ble_mfg_prob;
        document.getElementById('ble_refresh_ms').value = cfg.ble_refresh_ms;
        document.getElementById('ieee154_chan_mask').value = cfg.ieee154_chan_mask;
        document.getElementById('ieee154_beacon_ms').value = cfg.ieee154_beacon_ms;
        document.getElementById('wifi_interval_ms').value = cfg.wifi_interval_ms;
        document.getElementById('softap_ssid').value = cfg.softap_ssid;
        document.getElementById('softap_pass').value = cfg.softap_pass;
    } catch (e) {
        console.error(e);
    }
}

async function fetchStatus() {
    try {
        const res = await fetch('/api/status');
        const st = await res.json();
        document.getElementById('stat-uptime').innerText = st.uptime + 's';
        document.getElementById('stat-heap').innerText = (st.free_heap / 1024).toFixed(1) + ' KB';
        document.getElementById('stat-ble').innerText = (st.ble_rate ?? 0) + '/s';
        document.getElementById('stat-154').innerText = (st.ieee154_rate ?? 0) + '/s';
        document.getElementById('stat-thread').innerText = (st.thread_rate ?? 0) + '/s';
        document.getElementById('stat-wifi').innerText = (st.wifi_rate ?? 0) + '/s';
        document.getElementById('stat-awdl').innerText = (st.awdl_rate ?? 0) + '/s';
        const badge = document.getElementById('threat-badge');
        const n = st.threats || 0;
        badge.textContent = n;
        badge.className = n > 0 ? 'badge-alert' : 'badge-zero';
        const jamEl = document.getElementById('jam-status');
        if (jamEl) {
            if (st.jam_active) {
                // band 1 = Wi-Fi MGMT flood (protocol-specific); band 2 = the ED energy
                // meter, which sees ANY 2.4 GHz carrier (BT / Wi-Fi / Zigbee) — so it's
                // labelled generically rather than "802.15.4".
                const bandName = st.jam_band === 3 ? 'Wi-Fi + 2.4 GHz RF' : st.jam_band === 2 ? '2.4 GHz RF' : 'Wi-Fi';
                // the 2.4 GHz RF (ED energy) band reports dBm; a Wi-Fi attack reports a frame-flood rate.
                const intensity = [];
                if (st.jam_band & 2) intensity.push((st.jam_peak ?? '?') + ' dBm');
                if (st.jam_band & 1) intensity.push((st.jam_rate ?? 0) + '/s');
                jamEl.textContent = 'JAMMED · ' + bandName + ' · ' + intensity.join(' · ') + ' · ' + (st.jam_dur ?? 0) + 's';
                jamEl.className = 'jam-status-alert';
            } else {
                jamEl.textContent = 'Clear';
                jamEl.className = 'jam-status-clear';
            }
        }
        document.getElementById('conn-status').className = 'status-badge';
        document.getElementById('conn-status').innerText = 'Connected';
    } catch (e) {
        document.getElementById('conn-status').className = 'status-badge offline';
        document.getElementById('conn-status').innerText = 'Disconnected';
    }
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function fmtMac(hex) {
    return (hex.match(/.{2}/g) || []).join(':').toUpperCase();
}
function rssiToRadius(rssi) {                  // -40 (close) -> 15, -90 (far) -> 88
    const v = Math.max(-90, Math.min(-40, rssi));
    return 15 + ((-40 - v) / 50) * 73;
}
function idToAngle(hex) {                       // stable, decorative (no real bearing)
    let h = 0;
    for (let i = 0; i < hex.length; i++) h = (h * 31 + hex.charCodeAt(i)) & 0xffff;
    return (h % 360) * Math.PI / 180;
}
// Build the static radar chrome (rings, sweep, center) exactly once, so the
// sweep animates continuously and isn't restarted on every poll.
function ensureRadarChrome(svg) {
    if (svg.querySelector('.radar-ring')) return;
    [88, 63, 38].forEach(r => {
        const c = document.createElementNS(SVG_NS, 'circle');
        c.setAttribute('cx', 100); c.setAttribute('cy', 100); c.setAttribute('r', r);
        c.setAttribute('class', 'radar-ring');
        svg.appendChild(c);
    });
    const sweep = document.createElementNS(SVG_NS, 'line');
    sweep.setAttribute('x1', 100); sweep.setAttribute('y1', 100);
    sweep.setAttribute('x2', 100); sweep.setAttribute('y2', 12);
    sweep.setAttribute('class', 'radar-sweep');
    svg.appendChild(sweep);
    const you = document.createElementNS(SVG_NS, 'circle');
    you.setAttribute('cx', 100); you.setAttribute('cy', 100); you.setAttribute('r', 3);
    you.setAttribute('class', 'radar-you');
    svg.appendChild(you);
}
function drawRadar(devices) {
    const svg = document.getElementById('radar');
    ensureRadarChrome(svg);
    // Update blips in place (keyed by id) so they glide via CSS transition and
    // the persistent sweep/chrome keeps animating.
    const seen = {};
    devices.forEach(d => {
        seen[d.id] = true;
        const rad = rssiToRadius(d.rssi), ang = idToAngle(d.id);
        const cx = (100 + rad * Math.cos(ang)).toFixed(1);
        const cy = (100 + rad * Math.sin(ang)).toFixed(1);
        let b = svg.querySelector('.blip[data-id="' + d.id + '"]');
        if (!b) {
            b = document.createElementNS(SVG_NS, 'circle');
            b.setAttribute('data-id', d.id);
            b.setAttribute('r', 5);
            b.appendChild(document.createElementNS(SVG_NS, 'title'));
            b.addEventListener('click', () => showBlip(b._dev));
            svg.appendChild(b);
        }
        b._dev = d;
        b.setAttribute('cx', cx);
        b.setAttribute('cy', cy);
        b.setAttribute('class', 'blip ' +
            (d.cat === 'threat' ? 'blip-threat' : d.cat === 'peer' ? 'blip-peer' : 'blip-trusted'));
        b.firstChild.textContent = fmtMac(d.id) + ' · ' + d.rssi + ' dBm';
    });
    // Drop blips for devices that are no longer present.
    svg.querySelectorAll('.blip').forEach(b => { if (!seen[b.getAttribute('data-id')]) b.remove(); });
}
function showBlip(d) {
    const el = document.getElementById('blip-detail');
    const isPeer = d.cat === 'peer';
    const isThreat = d.cat === 'threat' || isPeer;
    el.style.display = 'block';
    el.innerHTML = '<div class="bd-mac">' + fmtMac(d.id) + '</div>' +
        '<div class="bd-meta">' + d.rssi + ' dBm · ' + d.kind + ' · ' + d.radio.toUpperCase() +
        (isPeer ? ' · reported by another node' :
         d.cat === 'threat' ? ' · ' + d.minutes + ' min · ' + d.scenes + ' scenes' : '') + '</div>';
    const btn = document.createElement('button');
    btn.className = 'btn' + (isThreat ? ' danger' : '');
    btn.textContent = isThreat ? 'Trust (ignore)' : 'Untrust';
    btn.onclick = () => setAllow(d.id, isThreat);   // threat/peer -> trust; trusted -> untrust
    el.appendChild(btn);
}
async function setAllow(id, on) {
    await fetch('/api/allow', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id, on: on }) });
    document.getElementById('blip-detail').style.display = 'none';
    fetchRadar();
}
async function fetchRadar() {
    try {
        const res = await fetch('/api/radar');
        const data = await res.json();
        const devices = data.devices || [];
        drawRadar(devices);
        const rssiByMac = {};
        devices.forEach(d => { if (d.cat === 'trusted') rssiByMac[d.id] = d.rssi; });
        const trusted = data.trusted || [];
        const ul = document.getElementById('trusted-list');
        ul.innerHTML = '';
        trusted.forEach(id => {
            const li = document.createElement('li');
            const present = rssiByMac[id] !== undefined;
            const span = document.createElement('span');
            span.innerHTML = '<code>' + fmtMac(id) + '</code> <span class="meta">' +
                (present ? rssiByMac[id] + ' dBm' : 'out of range') + '</span>';
            const rm = document.createElement('button');
            rm.className = 'rm'; rm.textContent = '✕';
            rm.onclick = () => setAllow(id, false);
            li.appendChild(span); li.appendChild(rm);
            ul.appendChild(li);
        });
        document.getElementById('trusted-count').textContent = trusted.length;
        renderKindAlerts(data.kinds || []);
    } catch (e) { /* offline */ }
}

// Persistent threat journal (relative timestamps: boot counter + minutes-since-boot,
// since the device has no RTC).
let lastLog = [];
async function fetchThreatLog() {
    try {
        const res = await fetch('/api/threatlog');
        const data = await res.json();
        lastLog = data.log || [];
        document.getElementById('log-count').textContent = lastLog.length;
        const tbl = document.getElementById('log-table');
        if (!tbl) return;
        let html = '<tr><th>when</th><th>kind</th><th>MAC</th><th>dBm</th><th>min</th><th>sc</th></tr>';
        lastLog.forEach(e => {
            html += '<tr><td>b' + e.boot + '+' + e.uptime_min + 'm</td><td>' + e.kind +
                '</td><td><code>' + fmtMac(e.id) + '</code></td><td>' + e.rssi +
                '</td><td>' + e.minutes + '</td><td>' + e.scenes + '</td></tr>';
        });
        tbl.innerHTML = html;
    } catch (e) { /* offline */ }
}
// Jam episode journal (relative timestamps: boot counter + minutes-since-boot,
// since the device has no RTC).
async function fetchJamLog() {
    try {
        const res = await fetch('/api/jamlog');
        const data = await res.json();
        const log = data.log || [];
        document.getElementById('jam-log-count').textContent = log.length;
        const tbl = document.getElementById('jam-log-table');
        if (!tbl) return;
        let html = '<tr><th>when</th><th>band</th><th>intensity</th><th>dur</th></tr>';
        if (log.length === 0) {
            html += '<tr><td colspan="4" style="color:#a1a1aa;">No jamming episodes recorded.</td></tr>';
        }
        log.forEach(e => {
            const band = e.band === 3 ? 'Wi-Fi + 2.4 GHz RF' : e.band === 2 ? '2.4 GHz RF' : 'Wi-Fi';
            const intensity = [];
            if (e.band & 2) intensity.push(e.peak + ' dBm');
            if (e.band & 1) intensity.push((e.rate ?? 0) + '/s');
            html += '<tr><td>b' + e.boot + '+' + e.uptime_min + 'm</td><td>' + band +
                '</td><td>' + intensity.join(' · ') + '</td><td>' + e.dur + 's</td></tr>';
        });
        tbl.innerHTML = html;
    } catch (e) { /* offline */ }
}

function downloadLogCsv() {
    const rows = [['boot', 'uptime_min', 'kind', 'mac', 'rssi', 'minutes', 'scenes']];
    lastLog.forEach(e => rows.push([e.boot, e.uptime_min, e.kind, fmtMac(e.id), e.rssi, e.minutes, e.scenes]));
    const csv = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'splinter-threats.csv';
    a.click();
    URL.revokeObjectURL(a.href);
}

// Kind-level tracker alerts: a commercial tracker (AirTag/SmartTag/Tile) rotates
// its MAC, so it's detected at the kind level — "N present vs your baseline".
function renderKindAlerts(kinds) {
    const box = document.getElementById('kind-alerts');
    if (!box) return;
    if (!kinds.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
    box.style.display = '';
    box.innerHTML = kinds.map(k => {
        const extra = Math.max(0, (k.present || 0) - (k.baseline || 0));
        return '⚠ <strong>' + k.kind + '</strong> tracker following you — ' +
            k.present + ' present, ' + k.baseline + ' expected' +
            ' (' + extra + ' unexplained, survived ' + k.scenes + ' moves)';
    }).join('<br>');
}
