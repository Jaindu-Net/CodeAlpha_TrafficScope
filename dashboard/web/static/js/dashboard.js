/* TrafficScope SOC Web Dashboard Controller (Strict XSS-safe DOM rendering) */
"use strict";

(() => {
  const PROTO_COLORS = {
    TCP: "#06b6d4",
    HTTP: "#10b981",
    TLS: "#8b5cf6",
    DNS: "#3b82f6",
    UDP: "#f59e0b",
    ICMP: "#ec4899",
    ARP: "#64748b",
  };

  const state = {
    elevated: false,
    running: false,
    activeTab: "packets",
    severityFilter: "ALL",
    searchTerm: "",
    telemetry: null,
    flows: [],
    timelineChart: null,
    protocolChart: null,
    currentTranscript: "",
    pollTimer: null,
    pollInFlight: false,
  };

  const el = {
    sourceLabel: document.getElementById("source-label"),
    modePill: document.getElementById("mode-pill"),
    modeText: document.getElementById("mode-text"),
    elevationPill: document.getElementById("elevation-pill"),
    ifaceSelect: document.getElementById("iface-select"),
    bpfInput: document.getElementById("bpf-input"),
    btnRefreshIfaces: document.getElementById("btn-refresh-ifaces"),
    btnToggleAdvanced: document.getElementById("btn-toggle-advanced"),
    advancedDrawer: document.getElementById("advanced-drawer"),
    btnStartLive: document.getElementById("btn-start-live"),
    btnStop: document.getElementById("btn-stop"),
    btnReplayUpload: document.getElementById("btn-replay-upload"),
    pcapFileInput: document.getElementById("pcap-file-input"),
    btnReplayPath: document.getElementById("btn-replay-path"),
    optHttpPorts: document.getElementById("opt-http-ports"),
    optThreads: document.getElementById("opt-threads"),
    optBaseline: document.getElementById("opt-baseline"),
    optCount: document.getElementById("opt-count"),
    optPayloadBytes: document.getElementById("opt-payload-bytes"),
    optNoPayload: document.getElementById("opt-no-payload"),
    optLocalPcap: document.getElementById("opt-local-pcap"),
    btnExportPcap: document.getElementById("btn-export-pcap"),
    exportFormatSelect: document.getElementById("export-format-select"),
    btnExportSelected: document.getElementById("btn-export-selected"),
    feedbackBanner: document.getElementById("feedback-banner"),
    feedbackText: document.getElementById("feedback-text"),
    btnCloseBanner: document.getElementById("btn-close-banner"),
    kpiPackets: document.getElementById("kpi-packets"),
    kpiPps: document.getElementById("kpi-pps"),
    kpiBytes: document.getElementById("kpi-bytes"),
    kpiStreams: document.getElementById("kpi-streams"),
    kpiHosts: document.getElementById("kpi-hosts"),
    kpiHttp: document.getElementById("kpi-http"),
    kpiAlertBox: document.getElementById("kpi-alert-box"),
    kpiAnomalies: document.getElementById("kpi-anomalies"),
    kpiAnomalyTypes: document.getElementById("kpi-anomaly-types"),
    kpiDrops: document.getElementById("kpi-drops"),
    kpiKernelDrops: document.getElementById("kpi-kernel-drops"),
    kpiElapsed: document.getElementById("kpi-elapsed"),
    kpiCompletion: document.getElementById("kpi-completion"),
    chartRateCaption: document.getElementById("chart-rate-caption"),
    protoTotalCaption: document.getElementById("proto-total-caption"),
    protocolLegend: document.getElementById("protocol-legend"),
    entropySummary: document.getElementById("entropy-summary"),
    topHostsList: document.getElementById("top-hosts-list"),
    timelineCanvas: document.getElementById("timeline-chart"),
    timelineFallback: document.getElementById("timeline-fallback"),
    protocolCanvas: document.getElementById("protocol-chart"),
    protocolFallback: document.getElementById("protocol-fallback"),
    searchInput: document.getElementById("search-input"),
    badgePackets: document.getElementById("badge-packets"),
    badgeFlows: document.getElementById("badge-flows"),
    badgeAlerts: document.getElementById("badge-alerts"),
    badgeMeta: document.getElementById("badge-meta"),
    badgeHttp: document.getElementById("badge-http"),
    packetsTbody: document.getElementById("packets-tbody"),
    flowsTbody: document.getElementById("flows-tbody"),
    alertsTbody: document.getElementById("alerts-tbody"),
    dnsTbody: document.getElementById("dns-tbody"),
    tlsTbody: document.getElementById("tls-tbody"),
    httpTbody: document.getElementById("http-tbody"),
    streamModal: document.getElementById("stream-modal"),
    modalFlowLabel: document.getElementById("modal-flow-label"),
    modalHttpSummary: document.getElementById("modal-http-summary"),
    streamTranscript: document.getElementById("stream-transcript"),
    btnCopyStream: document.getElementById("btn-copy-stream"),
    btnCloseModal: document.getElementById("btn-close-modal"),
  };

  function formatBytes(num) {
    if (!Number.isFinite(num) || num <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let val = num;
    let idx = 0;
    while (val >= 1024 && idx < units.length - 1) {
      val /= 1024;
      idx += 1;
    }
    return idx === 0 ? `${Math.round(val)} B` : `${val.toFixed(1)} ${units[idx]}`;
  }

  function formatDuration(seconds) {
    const safe = Math.max(0, Number(seconds) || 0);
    const mins = Math.floor(safe / 60);
    const secs = (safe % 60).toFixed(1).padStart(4, "0");
    return `${String(mins).padStart(2, "0")}:${secs}`;
  }

  function formatTimestamp(ts) {
    if (!ts) return "--:--:--";
    const dt = new Date(Number(ts) * 1000);
    return Number.isNaN(dt.getTime()) ? "--:--:--" : dt.toLocaleTimeString();
  }

  function showBanner(message, isInfo = false) {
    el.feedbackText.textContent = message;
    el.feedbackBanner.classList.remove("hidden", "banner-info");
    if (isInfo) el.feedbackBanner.classList.add("banner-info");
  }

  function hideBanner() {
    el.feedbackBanner.classList.add("hidden");
  }

  function collectPipelineOptions() {
    const opts = {
      iface: el.ifaceSelect.value || undefined,
      bpf_filter: el.bpfInput.value.trim() || undefined,
      http_ports: el.optHttpPorts.value.trim() || undefined,
      baseline_seconds: el.optBaseline.value || undefined,
      no_payload: el.optNoPayload.checked,
    };
    if (el.optThreads.value.trim()) opts.threads = Number(el.optThreads.value);
    if (el.optCount.value.trim()) opts.count = Number(el.optCount.value);
    if (el.optPayloadBytes.value.trim()) opts.payload_bytes = Number(el.optPayloadBytes.value);
    return opts;
  }

  async function apiRequest(url, options = {}) {
    const resp = await fetch(url, options);
    const contentType = resp.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await resp.json() : null;
    if (!resp.ok) {
      const msg = data && data.error ? data.error : `Request failed (${resp.status})`;
      throw new Error(msg);
    }
    return data;
  }

  async function loadInterfaces() {
    try {
      const data = await apiRequest("/api/interfaces");
      state.elevated = Boolean(data.elevated);
      el.elevationPill.textContent = state.elevated ? "ADMIN ELEVATED" : "NON-ADMIN (REPLAY OK)";
      el.elevationPill.className = `pill ${state.elevated ? "pill-live" : "pill-warn"}`;

      const prevValue = el.ifaceSelect.value;
      el.ifaceSelect.replaceChildren();
      const interfaces = data.interfaces || [];
      if (interfaces.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No network interfaces detected";
        el.ifaceSelect.appendChild(opt);
      } else {
        let defaultValue = "";
        for (const item of interfaces) {
          const opt = document.createElement("option");
          opt.value = item.name;
          const cardName = item.description || item.name || "Unknown Adapter";
          const hasIp = Boolean(item.ip && item.ip !== "N/A");
          opt.textContent = hasIp ? `${cardName} — ${item.ip}` : cardName;
          opt.title = hasIp ? `${cardName} (${item.name}) — ${item.ip}` : `${cardName} (${item.name})`;
          if (!defaultValue && hasIp && item.ip !== "127.0.0.1") {
            defaultValue = item.name;
          }
          el.ifaceSelect.appendChild(opt);
        }
        if (prevValue && interfaces.some((i) => i.name === prevValue)) {
          el.ifaceSelect.value = prevValue;
        } else if (defaultValue) {
          el.ifaceSelect.value = defaultValue;
        }
      }
      updateActionButtons();
    } catch (err) {
      showBanner(`Interface scan failed: ${err.message}`);
    }
  }

  function updateActionButtons() {
    const t = state.telemetry;
    const running = Boolean(t && t.running);
    state.running = running;

    el.btnStartLive.disabled = running || !state.elevated || !el.ifaceSelect.value;
    el.btnStartLive.title = state.elevated
      ? "Start live packet capture on selected interface"
      : "Live capture requires launching TrafficScope as Administrator";
    el.btnStop.disabled = !running;
    el.btnReplayUpload.disabled = running;
    el.btnReplayPath.disabled = running;

    const canExportPcap = Boolean(t && t.has_pcap_export);
    const canExportData = Boolean(t && t.has_flows_export);
    el.btnExportPcap.classList.toggle("disabled-link", !canExportPcap);
    el.btnExportPcap.setAttribute("aria-disabled", String(!canExportPcap));
    el.btnExportSelected.disabled = !canExportData;
    el.exportFormatSelect.disabled = !canExportData;
  }

  function makeProtoBadge(proto) {
    const span = document.createElement("span");
    const known = PROTO_COLORS[proto] ? proto : "OTHER";
    span.className = `proto-badge proto-${known}`;
    span.textContent = proto || "OTHER";
    return span;
  }

  function makeCell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function renderEmptyRow(tbody, colspan, message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colspan;
    td.className = "empty-cell";
    td.textContent = message;
    tr.appendChild(td);
    tbody.replaceChildren(tr);
  }

  function renderHeaderAndKpis(t) {
    el.sourceLabel.textContent = t.source_label || "Idle";

    if (t.running && t.mode === "live") {
      el.modePill.className = "pill pill-live";
      el.modeText.textContent = "LIVE CAPTURE";
    } else if (t.running && t.mode === "replay") {
      el.modePill.className = "pill pill-replay";
      el.modeText.textContent = "REPLAYING PCAP";
    } else if (t.capture_complete) {
      el.modePill.className = "pill pill-replay";
      el.modeText.textContent = `${String(t.mode || "session").toUpperCase()} DONE`;
    } else {
      el.modePill.className = "pill pill-neutral";
      el.modeText.textContent = "IDLE";
    }

    el.kpiPackets.textContent = Number(t.total_packets || 0).toLocaleString();
    el.kpiPps.textContent = `${Number(t.current_pps || 0).toFixed(1)} pps (avg ${Number(t.avg_pps || 0).toFixed(1)} / peak ${Number(t.peak_pps || 0).toFixed(1)})`;
    el.kpiBytes.textContent = formatBytes(t.total_bytes || 0);
    el.kpiStreams.textContent = `${t.stream_count || 0} TCP streams tracked`;
    el.kpiHosts.textContent = String((t.top_hosts || []).length);
    el.kpiHttp.textContent = `${t.http_exchange_count || 0} HTTP exchanges`;

    const anomalyTotal = Number(t.total_anomalies || 0);
    el.kpiAnomalies.textContent = anomalyTotal.toLocaleString();
    el.kpiAlertBox.classList.toggle("has-alerts", anomalyTotal > 0);
    const anomalyEntries = Object.entries(t.anomaly_counts || {});
    el.kpiAnomalyTypes.textContent = anomalyEntries.length
      ? anomalyEntries.map(([k, v]) => `${k}: ${v}`).join(" | ")
      : "No active threat triggers";

    el.kpiDrops.textContent = Number(t.dropped_packets || 0).toLocaleString();
    el.kpiKernelDrops.textContent =
      t.kernel_dropped === null || t.kernel_dropped === undefined
        ? "Kernel drops: n/a"
        : `Kernel drops: ${t.kernel_dropped}`;
    el.kpiElapsed.textContent = formatDuration(t.elapsed_s);
    el.kpiCompletion.textContent = t.running
      ? "Capturing packets in real time..."
      : t.capture_complete
        ? "Capture complete — exports ready"
        : "Select NIC or PCAP file to begin";

    if (t.last_error) {
      showBanner(t.last_error);
    }

    updateActionButtons();
  }

  function formatEndpoint(ip, port) {
    if (!ip) return "-";
    return port !== null && port !== undefined && port !== "" ? `${ip}:${port}` : ip;
  }

  function renderTimeline(t) {
    const timeline = t.timeline || [];
    const labels = timeline.map((pt) => pt.time);
    const rates = timeline.map((pt) => pt.pps);
    const kbytesSeries = timeline.map((pt) => Number(((pt.bytes || 0) / 1024).toFixed(2)));

    el.chartRateCaption.textContent = `${timeline.length}s samples | Peak ${Number(t.peak_pps || 0).toFixed(1)} pps`;

    if (typeof window.Chart !== "function") {
      el.timelineCanvas.classList.add("hidden");
      el.timelineFallback.classList.remove("hidden");
      if (!timeline.length) {
        const p = document.createElement("span");
        p.className = "panel-caption";
        p.textContent = "No timeline samples yet.";
        el.timelineFallback.replaceChildren(p);
        return;
      }
      const peak = Math.max(1, ...rates);
      const rows = timeline.slice(-10).map((pt) => {
        const row = document.createElement("div");
        row.className = "bar-row mono";
        const lbl = document.createElement("span");
        lbl.textContent = pt.time;
        const track = document.createElement("div");
        track.className = "bar-track";
        const fill = document.createElement("div");
        fill.className = "bar-fill";
        fill.style.width = `${Math.round((pt.pps / peak) * 100)}%`;
        track.appendChild(fill);
        const val = document.createElement("span");
        val.textContent = `${pt.pps} pps`;
        row.append(lbl, track, val);
        return row;
      });
      el.timelineFallback.replaceChildren(...rows);
      return;
    }

    el.timelineCanvas.classList.remove("hidden");
    el.timelineFallback.classList.add("hidden");

    if (!state.timelineChart) {
      state.timelineChart = new window.Chart(el.timelineCanvas.getContext("2d"), {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "Packets / s",
              data: rates,
              borderColor: "#06b6d4",
              backgroundColor: "rgba(6, 182, 212, 0.16)",
              fill: true,
              tension: 0.25,
              borderWidth: 2,
              pointRadius: 2,
            },
            {
              label: "KB / s",
              data: kbytesSeries,
              borderColor: "#10b981",
              backgroundColor: "rgba(16, 185, 129, 0.28)",
              type: "bar",
              yAxisID: "y1",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          scales: {
            x: { ticks: { color: "#64748b", maxTicksLimit: 8 }, grid: { color: "rgba(148,163,184,0.08)" } },
            y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.08)" } },
            y1: { beginAtZero: true, position: "right", ticks: { color: "#6ee7b7" }, grid: { display: false } },
          },
          plugins: {
            legend: { labels: { color: "#cbd5e1", boxWidth: 12 } },
          },
        },
      });
    } else {
      state.timelineChart.data.labels = labels;
      state.timelineChart.data.datasets[0].data = rates;
      state.timelineChart.data.datasets[1].data = kbytesSeries;
      state.timelineChart.update("none");
    }
  }

  function renderProtocols(t) {
    const counts = t.protocol_counts || {};
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((sum, [, v]) => sum + v, 0);
    el.protoTotalCaption.textContent = `${total.toLocaleString()} pkts`;

    const legendItems = entries.map(([proto, count]) => {
      const li = document.createElement("li");
      li.className = "legend-item";
      const sw = document.createElement("span");
      sw.className = "legend-swatch";
      sw.style.background = PROTO_COLORS[proto] || "#64748b";
      const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
      const txt = document.createElement("span");
      txt.textContent = `${proto}: ${pct}% (${count})`;
      li.append(sw, txt);
      return li;
    });
    el.protocolLegend.replaceChildren(...legendItems);

    const labels = entries.map(([k]) => k);
    const values = entries.map(([, v]) => v);
    const colors = labels.map((k) => PROTO_COLORS[k] || "#64748b");

    if (typeof window.Chart !== "function") {
      el.protocolCanvas.classList.add("hidden");
      el.protocolFallback.classList.remove("hidden");
      const rows = entries.slice(0, 6).map(([proto, count]) => {
        const row = document.createElement("div");
        row.className = "bar-row mono";
        const lbl = document.createElement("span");
        lbl.textContent = proto;
        const track = document.createElement("div");
        track.className = "bar-track";
        const fill = document.createElement("div");
        fill.className = "bar-fill";
        fill.style.width = `${total > 0 ? Math.round((count / total) * 100) : 0}%`;
        fill.style.background = PROTO_COLORS[proto] || "#64748b";
        track.appendChild(fill);
        const val = document.createElement("span");
        val.textContent = String(count);
        row.append(lbl, track, val);
        return row;
      });
      el.protocolFallback.replaceChildren(...rows);
      return;
    }

    el.protocolCanvas.classList.remove("hidden");
    el.protocolFallback.classList.add("hidden");

    if (!state.protocolChart) {
      state.protocolChart = new window.Chart(el.protocolCanvas.getContext("2d"), {
        type: "doughnut",
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          cutout: "64%",
          plugins: { legend: { display: false } },
        },
      });
    } else {
      state.protocolChart.data.labels = labels;
      state.protocolChart.data.datasets[0].data = values;
      state.protocolChart.data.datasets[0].backgroundColor = colors;
      state.protocolChart.update("none");
    }
  }

  function renderEntropyAndHosts(t) {
    const summary = t.entropy_summary || {};
    const rows = [
      { key: "plaintext", label: "Plaintext (<3.5)", cls: "bar-fill-green", val: summary.plaintext || 0 },
      { key: "mixed", label: "Compressed / Mixed (3.5-6.5)", cls: "bar-fill-amber", val: summary["compressed/mixed"] || 0 },
      { key: "encrypted", label: "Encrypted (>6.5)", cls: "bar-fill-red", val: summary["likely encrypted"] || 0 },
    ];
    const total = Math.max(1, rows.reduce((acc, r) => acc + r.val, 0));

    const barEls = rows.map((r) => {
      const row = document.createElement("div");
      row.className = "bar-row mono";
      const lbl = document.createElement("span");
      lbl.textContent = r.label.split(" ")[0];
      lbl.title = r.label;
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = `bar-fill ${r.cls}`;
      fill.style.width = `${Math.round((r.val / total) * 100)}%`;
      track.appendChild(fill);
      const val = document.createElement("span");
      val.textContent = `${r.val} flows`;
      row.append(lbl, track, val);
      return row;
    });
    el.entropySummary.replaceChildren(...barEls);

    const hosts = t.top_hosts || [];
    if (!hosts.length) {
      const msg = document.createElement("span");
      msg.className = "panel-caption";
      msg.textContent = "No hosts observed yet.";
      el.topHostsList.replaceChildren(msg);
      return;
    }

    const hostEls = hosts.slice(0, 6).map((h) => {
      const item = document.createElement("div");
      item.className = "mini-host-item";
      const left = document.createElement("span");
      left.textContent = h.os_guess ? `${h.ip} (${h.os_guess})` : h.ip;
      const right = document.createElement("span");
      right.textContent = `${formatBytes(h.bytes)} | ${h.protocol}`;
      item.append(left, right);
      return item;
    });
    el.topHostsList.replaceChildren(...hostEls);
  }

  function matchesFilter(...fields) {
    if (!state.searchTerm) return true;
    const q = state.searchTerm;
    return fields.some((val) => val && String(val).toLowerCase().includes(q));
  }

  function renderPacketsTable(t) {
    const packets = t.recent_packets || [];
    el.badgePackets.textContent = String(packets.length);

    const filtered = packets.filter((p) =>
      matchesFilter(p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol, p.info)
    );
    if (!filtered.length) {
      renderEmptyRow(el.packetsTbody, 7, "No matching packets captured yet.");
      return;
    }

    const rows = filtered.map((p) => {
      const tr = document.createElement("tr");
      const protoTd = document.createElement("td");
      protoTd.appendChild(makeProtoBadge(p.protocol));
      tr.append(
        makeCell(String(p.id || "-")),
        makeCell(p.time || "--:--:--"),
        makeCell(formatEndpoint(p.src_ip, p.src_port)),
        makeCell(formatEndpoint(p.dst_ip, p.dst_port)),
        protoTd,
        makeCell(`${p.length || 0} B`),
        makeCell(p.info || "-")
      );
      return tr;
    });
    el.packetsTbody.replaceChildren(...rows);
  }

  function renderFlowsTable() {
    const flows = state.flows || [];
    el.badgeFlows.textContent = String(flows.length);
    const filtered = flows.filter((f) =>
      matchesFilter(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol, f.src_os, f.dst_os)
    );
    if (!filtered.length) {
      renderEmptyRow(el.flowsTbody, 8, "No flows match the current filter.");
      return;
    }

    const rows = filtered.map((f) => {
      const tr = document.createElement("tr");
      const endpointText = `${f.src_ip}:${f.src_port} -> ${f.dst_ip}:${f.dst_port}`;
      const osLabel = f.src_os
        ? `${f.src_os}${f.os_confidence ? ` (${f.os_confidence}%)` : ""}`
        : f.dst_os || "Unknown";

      const protoTd = document.createElement("td");
      protoTd.appendChild(makeProtoBadge(f.protocol));

      const actionTd = document.createElement("td");
      if (f.has_stream && f.flow_id) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-secondary btn-sm";
        btn.textContent = "Follow Stream";
        btn.addEventListener("click", () => openStreamModal(f.flow_id, endpointText));
        actionTd.appendChild(btn);
      } else {
        actionTd.textContent = "-";
      }

      tr.append(
        makeCell(endpointText),
        protoTd,
        makeCell(osLabel),
        makeCell(String(f.packet_count)),
        makeCell(formatBytes(f.byte_count)),
        makeCell(`${Number(f.duration_s || 0).toFixed(2)}s`),
        makeCell(`${Number(f.mean_entropy || 0).toFixed(2)} (${f.entropy_label || "n/a"})`),
        actionTd
      );
      return tr;
    });
    el.flowsTbody.replaceChildren(...rows);
  }

  function renderAlertsTable(t) {
    const alerts = [...(t.alerts_serialized || [])].reverse();
    el.badgeAlerts.textContent = String(alerts.length);

    const filtered = alerts.filter((a) => {
      if (state.severityFilter !== "ALL" && a.severity !== state.severityFilter) {
        return false;
      }
      return matchesFilter(a.type, a.src_ip, a.dst_ip, a.detail);
    });
    if (!filtered.length) {
      renderEmptyRow(el.alertsTbody, 5, "No security alerts match the current filter.");
      return;
    }

    const rows = filtered.map((a) => {
      const tr = document.createElement("tr");
      const sevTd = document.createElement("td");
      const sevBadge = document.createElement("span");
      sevBadge.className = `sev-badge sev-${a.severity || "LOW"}`;
      sevBadge.textContent = a.severity || "LOW";
      sevTd.appendChild(sevBadge);

      const target = a.dst_ip ? `${a.src_ip} -> ${a.dst_ip}` : a.src_ip;
      tr.append(
        makeCell(a.time_str || formatTimestamp(a.timestamp)),
        sevTd,
        makeCell(a.type || "-"),
        makeCell(target || "-"),
        makeCell(a.detail || "-")
      );
      return tr;
    });
    el.alertsTbody.replaceChildren(...rows);
  }

  function renderMetadataTables(t) {
    const dnsList = [...(t.dns_records || [])].reverse();
    const tlsList = [...(t.tls_sessions || [])].reverse();
    el.badgeMeta.textContent = String(dnsList.length + tlsList.length);

    const filteredDns = dnsList.filter((d) =>
      matchesFilter(d.src_ip, d.query, d.qtype, ...(d.answers || []))
    );
    if (!filteredDns.length) {
      renderEmptyRow(el.dnsTbody, 4, "No DNS metadata observed.");
    } else {
      el.dnsTbody.replaceChildren(
        ...filteredDns.map((d) => {
          const tr = document.createElement("tr");
          const kindLabel = `${d.is_response ? "RESP" : "QUERY"} ${d.qtype || ""}`.trim();
          const ansList = d.answers && d.answers.length ? ` -> ${d.answers.join(", ")}` : "";
          tr.append(
            makeCell(d.time || "--:--:--"),
            makeCell(d.src_ip || "-"),
            makeCell(kindLabel),
            makeCell(`${d.query || "-"}${ansList}`)
          );
          return tr;
        })
      );
    }

    const filteredTls = tlsList.filter((s) =>
      matchesFilter(s.src_ip, s.dst_ip, s.sni, s.version, ...(s.alpn || []))
    );
    if (!filteredTls.length) {
      renderEmptyRow(el.tlsTbody, 4, "No TLS SNI handshakes observed.");
    } else {
      el.tlsTbody.replaceChildren(
        ...filteredTls.map((s) => {
          const tr = document.createElement("tr");
          const alpnTxt = s.alpn && s.alpn.length ? ` [${s.alpn.join(", ")}]` : "";
          const verTxt = `${s.version || "TLS"} (${s.cipher_count || 0} ciphers)`;
          tr.append(
            makeCell(s.time || "--:--:--"),
            makeCell(`${s.src_ip} -> ${s.dst_ip}`),
            makeCell(verTxt),
            makeCell(`${s.sni || "(no SNI)"}${alpnTxt}`)
          );
          return tr;
        })
      );
    }
  }

  function renderHttpTable(t) {
    const list = t.http_exchanges || [];
    el.badgeHttp.textContent = String(list.length);
    const filtered = list.filter((ex) => {
      const req = ex.request || {};
      const resp = ex.response || {};
      return matchesFilter(ex.client, ex.server, req.method, req.path, req.host, resp.status_code);
    });
    if (!filtered.length) {
      renderEmptyRow(el.httpTbody, 5, "No reconstructed HTTP sessions found.");
      return;
    }

    const rows = filtered.map((ex) => {
      const tr = document.createElement("tr");
      const req = ex.request;
      const resp = ex.response;
      const reqText = req ? `${req.method} ${req.path} (${req.version})` : "(mid-stream response only)";
      const hostText = req && req.host ? req.host : ex.server;
      const statusText = resp ? `${resp.status_code} ${resp.reason}`.trim() : "(no response yet)";

      const actionTd = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-secondary btn-sm";
      btn.textContent = "Inspect Stream";
      btn.addEventListener("click", () => openStreamModal(ex.flow_id, `${ex.client} -> ${ex.server}`));
      actionTd.appendChild(btn);

      tr.append(
        makeCell(`${ex.client} -> ${ex.server}`),
        makeCell(reqText),
        makeCell(hostText),
        makeCell(statusText),
        actionTd
      );
      return tr;
    });
    el.httpTbody.replaceChildren(...rows);
  }

  function renderAll() {
    if (!state.telemetry) return;
    const t = state.telemetry;
    renderHeaderAndKpis(t);
    renderTimeline(t);
    renderProtocols(t);
    renderEntropyAndHosts(t);
    renderPacketsTable(t);
    renderFlowsTable();
    renderAlertsTable(t);
    renderMetadataTables(t);
    renderHttpTable(t);
  }

  async function refreshData() {
    if (state.pollInFlight) return;
    state.pollInFlight = true;
    try {
      const [telemetry, flowPayload] = await Promise.all([
        apiRequest("/api/telemetry"),
        apiRequest("/api/flows?limit=200"),
      ]);
      state.telemetry = telemetry;
      state.flows = flowPayload.flows || [];
      renderAll();
    } catch (err) {
      showBanner(`Telemetry sync warning: ${err.message}`);
    } finally {
      state.pollInFlight = false;
    }
  }

  function schedulePolling() {
    if (state.pollTimer) clearTimeout(state.pollTimer);
    const delayMs = state.running ? 900 : 2500;
    state.pollTimer = setTimeout(async () => {
      await refreshData();
      schedulePolling();
    }, delayMs);
  }

  async function handleStartLive() {
    hideBanner();
    try {
      await apiRequest("/api/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(collectPipelineOptions()),
      });
      await refreshData();
      showBanner("Live capture started.", true);
    } catch (err) {
      showBanner(err.message);
    }
  }

  async function handleStop() {
    try {
      await apiRequest("/api/capture/stop", { method: "POST" });
      await refreshData();
      showBanner("Capture stopped cleanly. Exports ready.", true);
    } catch (err) {
      showBanner(err.message);
    }
  }

  async function handleUploadFile(file) {
    if (!file) return;
    hideBanner();
    const form = new FormData();
    form.append("file", file);
    const opts = collectPipelineOptions();
    for (const [key, val] of Object.entries(opts)) {
      if (val !== undefined && val !== "") {
        form.append(key, String(val));
      }
    }
    try {
      await apiRequest("/api/replay", { method: "POST", body: form });
      await refreshData();
      showBanner(`Loaded PCAP: ${file.name}`, true);
    } catch (err) {
      showBanner(err.message);
    } finally {
      el.pcapFileInput.value = "";
    }
  }

  async function handleReplayLocalPath() {
    const pathVal = el.optLocalPcap.value.trim();
    if (!pathVal) {
      showBanner("Enter a local .pcap file path first.");
      return;
    }
    hideBanner();
    const payload = { ...collectPipelineOptions(), path: pathVal };
    try {
      await apiRequest("/api/replay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      await refreshData();
      showBanner(`Loaded local PCAP path: ${pathVal}`, true);
    } catch (err) {
      showBanner(err.message);
    }
  }

  async function openStreamModal(flowId, label) {
    try {
      const data = await apiRequest(`/api/streams/${encodeURIComponent(flowId)}`);
      el.modalFlowLabel.textContent = label || data.flow_id;
      state.currentTranscript = data.transcript || "";

      if (data.http_exchange && (data.http_exchange.request || data.http_exchange.response)) {
        const items = [];
        const req = data.http_exchange.request;
        const resp = data.http_exchange.response;
        if (req) {
          const line = document.createElement("div");
          line.textContent = `HTTP Request: ${req.method} ${req.path} (${req.version}) | Host: ${req.host || "-"}`;
          items.push(line);
        }
        if (resp) {
          const line = document.createElement("div");
          line.textContent = `HTTP Response: ${resp.version} ${resp.status_code} ${resp.reason} | Body: ${resp.body_bytes} B`;
          items.push(line);
        }
        el.modalHttpSummary.replaceChildren(...items);
        el.modalHttpSummary.classList.remove("hidden");
      } else {
        el.modalHttpSummary.classList.add("hidden");
        el.modalHttpSummary.replaceChildren();
      }

      el.streamTranscript.replaceChildren();
      const lines = (data.transcript || "(Empty TCP stream)").split("\n");
      for (const line of lines) {
        const div = document.createElement("div");
        if (line.startsWith("[→ CLIENT]") || line.startsWith("[-> CLIENT]")) {
          div.className = "stream-dir-client";
        } else if (line.startsWith("[← SERVER]") || line.startsWith("[<- SERVER]")) {
          div.className = "stream-dir-server";
        }
        div.textContent = line || " ";
        el.streamTranscript.appendChild(div);
      }

      el.streamModal.classList.remove("hidden");
    } catch (err) {
      showBanner(`Could not open stream: ${err.message}`);
    }
  }

  function closeModal() {
    el.streamModal.classList.add("hidden");
  }

  async function handleExportSelected() {
    const url = el.exportFormatSelect.value;
    if (!url) return;
    hideBanner();
    try {
      const resp = await fetch(url);
      if (!resp.ok) {
        const ct = resp.headers.get("content-type") || "";
        const errData = ct.includes("application/json") ? await resp.json() : null;
        throw new Error((errData && errData.error) || `Export failed (${resp.status})`);
      }
      const blob = await resp.blob();
      const disp = resp.headers.get("content-disposition") || "";
      const match = /filename="?([^"]+)"?/i.exec(disp);
      const fallback = url.includes(".csv") || url.includes("/csv") ? "trafficscope_export.csv" : "trafficscope_export.json";
      const filename = match ? match[1] : fallback;

      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(blobUrl);
      showBanner(`Downloaded ${filename}`, true);
    } catch (err) {
      showBanner(err.message);
    }
  }

  function wireEvents() {
    el.btnRefreshIfaces.addEventListener("click", loadInterfaces);
    el.ifaceSelect.addEventListener("change", updateActionButtons);
    el.btnCloseBanner.addEventListener("click", hideBanner);

    el.btnToggleAdvanced.addEventListener("click", () => {
      const hidden = el.advancedDrawer.classList.toggle("hidden");
      el.btnToggleAdvanced.setAttribute("aria-expanded", String(!hidden));
    });

    el.btnStartLive.addEventListener("click", handleStartLive);
    el.btnStop.addEventListener("click", handleStop);
    el.btnExportSelected.addEventListener("click", handleExportSelected);
    el.btnReplayUpload.addEventListener("click", () => el.pcapFileInput.click());
    el.pcapFileInput.addEventListener("change", (evt) => {
      const files = evt.target.files;
      if (files && files[0]) handleUploadFile(files[0]);
    });
    el.btnReplayPath.addEventListener("click", handleReplayLocalPath);

    el.searchInput.addEventListener("input", () => {
      state.searchTerm = el.searchInput.value.trim().toLowerCase();
      renderAll();
    });

    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        state.activeTab = tab;
        document.querySelectorAll(".tab-btn").forEach((b) => {
          const active = b.dataset.tab === tab;
          b.classList.toggle("active", active);
          b.setAttribute("aria-selected", String(active));
        });
        document.querySelectorAll(".tab-panel").forEach((panel) => {
          panel.classList.toggle("active", panel.id === `tab-${tab}`);
        });
      });
    });

    document.querySelectorAll(".chip[data-sev]").forEach((chip) => {
      chip.addEventListener("click", () => {
        state.severityFilter = chip.dataset.sev || "ALL";
        document.querySelectorAll(".chip[data-sev]").forEach((c) => {
          c.classList.toggle("active", c === chip);
        });
        renderAll();
      });
    });

    el.btnCloseModal.addEventListener("click", closeModal);
    el.streamModal.addEventListener("click", (evt) => {
      if (evt.target === el.streamModal) closeModal();
    });
    document.addEventListener("keydown", (evt) => {
      if (evt.key === "Escape" && !el.streamModal.classList.contains("hidden")) {
        closeModal();
      }
    });

    el.btnCopyStream.addEventListener("click", async () => {
      if (!state.currentTranscript || !navigator.clipboard) return;
      try {
        await navigator.clipboard.writeText(state.currentTranscript);
        el.btnCopyStream.textContent = "Copied!";
        setTimeout(() => {
          el.btnCopyStream.textContent = "Copy Transcript";
        }, 1200);
      } catch (_err) {
        showBanner("Clipboard write permission denied by browser.");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", async () => {
    wireEvents();
    await loadInterfaces();
    await refreshData();
    schedulePolling();
  });
})();
