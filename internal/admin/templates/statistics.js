(() => {
  'use strict';

  const statusLabel = document.getElementById('connection-label');
  const statusRoot = document.getElementById('connection-state');
  const hostRange = document.getElementById('host-range');
  const proxyRange = document.getElementById('proxy-range');
  let stream;

  const number = (value) => value == null || value === '' || !Number.isFinite(Number(value)) ? null : Number(value);
  const set = (id, value) => {
    const target = document.getElementById(id);
    if (target) target.textContent = value == null ? '—' : String(value);
  };
  const formatCount = (value) => value == null ? null : Math.round(value).toLocaleString();
  const formatBytes = (value) => {
    if (value == null) return null;
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let amount = Math.max(0, value);
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
    return `${amount.toFixed(unit === 0 || amount >= 100 ? 0 : 1)} ${units[unit]}`;
  };
  const formatRate = (value) => {
    if (value == null) return null;
    const bits = value * 8;
    if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(1)} Mb/s`;
    if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} kb/s`;
    return `${Math.round(bits)} b/s`;
  };
  const percentage = (used, total) => used == null || total == null || total <= 0 ? null : Math.max(0, Math.min(100, used * 100 / total));
  const uptimeText = (value) => {
    if (value == null) return null;
    const days = Math.floor(value / 86400);
    const hours = Math.floor((value % 86400) / 3600);
    const minutes = Math.floor((value % 3600) / 60);
    return days ? `${days}d ${hours}h` : `${hours}h ${minutes}m`;
  };
  const usageText = (total, used) => {
    if (total == null || used == null) return null;
    const percent = percentage(used, total);
    return `${formatBytes(used)} / ${formatBytes(total)}${percent == null ? '' : ` (${percent.toFixed(1)}%)`}`;
  };

  function updateStatus(status) {
    const labels = { live: 'Live', partial: 'Partially available', disconnected: 'Reconnecting' };
    statusLabel.textContent = labels[status] || 'Waiting for metrics';
    statusRoot.dataset.status = status || 'waiting';
  }

  function updateLive(data) {
    updateStatus(data.status);
    const host = data.host;
    if (host) {
      const memory = usageText(number(host.memory_total_bytes), number(host.memory_used_bytes));
      const swap = usageText(number(host.swap_total_bytes), number(host.swap_used_bytes));
      const disk = usageText(number(host.disk_total_bytes), number(host.disk_used_bytes));
      set('host-cpu', host.cpu_percent == null ? null : `${Number(host.cpu_percent).toFixed(1)}%`);
      set('host-cpu-state', host.cpu_percent == null ? 'Unavailable' : 'Current host sample');
      set('host-memory', memory);
      set('host-memory-state', memory == null ? 'Unavailable' : `Available: ${formatBytes(number(host.memory_available_bytes))}`);
      set('host-swap', swap);
      set('host-swap-state', swap == null ? 'Unavailable' : 'Used / capacity');
      set('host-disk', disk);
      set('host-disk-state', disk == null ? 'Unavailable' : 'Used / capacity');
      set('host-in', formatRate(number(host.network_in_bytes_per_second)));
      set('host-out', formatRate(number(host.network_out_bytes_per_second)));
      const loads = [host.load_1, host.load_5, host.load_15];
      set('host-load', loads.some((item) => item == null) ? null : loads.map((item) => Number(item).toFixed(2)).join(' / '));
      set('host-uptime', uptimeText(number(host.uptime_seconds)));
      set('host-in-current', formatRate(number(host.network_in_bytes_per_second)));
      set('host-out-current', formatRate(number(host.network_out_bytes_per_second)));
      set('host-in-total', formatBytes(number(host.network_in_total_bytes)));
      set('host-out-total', formatBytes(number(host.network_out_total_bytes)));
      document.getElementById('disk-empty').hidden = host.disk_total_bytes == null || host.disk_used_bytes == null || host.disk_free_bytes == null;
      document.getElementById('network-current-empty').hidden = host.network_in_bytes_per_second != null || host.network_out_bytes_per_second != null || host.network_in_total_bytes != null || host.network_out_total_bytes != null;
      if (host.disk_total_bytes > 0 && host.disk_used_bytes != null) {
        document.getElementById('disk-used-bar').style.width = `${percentage(host.disk_used_bytes, host.disk_total_bytes)}%`;
      }
      set('disk-used-label', formatBytes(number(host.disk_used_bytes)));
      set('disk-free-label', formatBytes(number(host.disk_free_bytes)));
    } else {
      ['host-cpu', 'host-memory', 'host-swap', 'host-disk', 'host-in', 'host-out', 'host-load', 'host-uptime', 'host-in-current', 'host-out-current', 'host-in-total', 'host-out-total', 'disk-used-label', 'disk-free-label'].forEach((id) => set(id, null));
      ['host-cpu-state', 'host-memory-state', 'host-swap-state', 'host-disk-state'].forEach((id) => set(id, 'Unavailable'));
      document.getElementById('disk-empty').hidden = false;
      document.getElementById('network-current-empty').hidden = false;
      document.getElementById('disk-used-bar').style.width = '0';
    }
    const proxy = data.proxy;
    if (proxy) {
      set('proxy-active', formatCount(number(proxy.active_requests)));
      set('proxy-rate', proxy.requests_per_second == null ? null : `${Number(proxy.requests_per_second).toFixed(2)} req/s`);
      set('proxy-allowed', formatCount(number(proxy.allowed_requests)));
      set('proxy-blocked', formatCount(number(proxy.blocked_requests)));
      set('proxy-errors', proxy.error_rate_percent == null ? null : `${Number(proxy.error_rate_percent).toFixed(2)}% (${formatCount(number(proxy.http_error_count))})`);
      set('proxy-in', formatRate(number(proxy.incoming_bytes_per_second)));
      set('proxy-out', formatRate(number(proxy.outgoing_bytes_per_second)));
      set('proxy-total', formatBytes(number(proxy.total_transferred_bytes)));
    } else {
      ['proxy-active', 'proxy-rate', 'proxy-allowed', 'proxy-blocked', 'proxy-errors', 'proxy-in', 'proxy-out', 'proxy-total'].forEach((id) => set(id, null));
    }
  }

  function pointsFor(series, samples) {
    return samples.map((sample) => {
      const host = sample.host;
      const proxy = sample.proxy;
      switch (series) {
        case 'host.cpu_percent': return number(host && host.cpu_percent);
        case 'host.memory_used_bytes': return percentage(number(host && host.memory_used_bytes), number(host && host.memory_total_bytes));
        case 'host.swap_used_bytes': return percentage(number(host && host.swap_used_bytes), number(host && host.swap_total_bytes));
        case 'host.disk_used_bytes': return percentage(number(host && host.disk_used_bytes), number(host && host.disk_total_bytes));
        case 'host.network_in_bytes_per_second': return number(host && host.network_in_bytes_per_second);
        case 'host.network_out_bytes_per_second': return number(host && host.network_out_bytes_per_second);
        case 'host.network': return [number(host && host.network_in_bytes_per_second), number(host && host.network_out_bytes_per_second)];
        case 'proxy.requests_per_second': return number(proxy && proxy.requests_per_second);
        case 'proxy.bandwidth': return [number(proxy && proxy.incoming_bytes_per_second), number(proxy && proxy.outgoing_bytes_per_second)];
        case 'proxy.requests': return [number(proxy && proxy.allowed_requests), number(proxy && proxy.blocked_requests)];
        case 'proxy.http_error_count': return number(proxy && proxy.http_error_count);
        default: return null;
      }
    });
  }

  function drawLine(polyline, values) {
    const valid = values.map((value, index) => ({ value, index })).filter((item) => Number.isFinite(item.value));
    if (!polyline) return;
    if (!valid.length) { polyline.setAttribute('points', ''); return; }
    const min = Math.min(...valid.map((item) => item.value));
    const max = Math.max(...valid.map((item) => item.value));
    const span = max - min || Math.abs(max) || 1;
    const points = valid.map((item) => {
      const x = valid.length === 1 ? 320 : item.index * 640 / Math.max(values.length - 1, 1);
      const y = 170 - (item.value - min) * 150 / span;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    polyline.setAttribute('points', points);
  }

  function drawCharts(samples, section) {
    section.querySelectorAll('.history-chart, .sparkline').forEach((chart) => {
      const series = chart.dataset.series;
      const values = pointsFor(series, samples);
      const multi = ['host.network', 'proxy.bandwidth', 'proxy.requests'].includes(series);
      if (multi) {
        drawLine(chart.querySelector('.series-in'), values.map((value) => value && value[0]));
        drawLine(chart.querySelector('.series-out'), values.map((value) => value && value[1]));
      } else {
        drawLine(chart.querySelector('polyline'), values);
      }
      if (chart.classList.contains('history-chart')) {
        const empty = chart.parentElement.querySelector('.chart-empty');
        if (empty) empty.hidden = samples.length > 0 && values.some((value) => Array.isArray(value) ? value.some(Number.isFinite) : Number.isFinite(value));
      }
    });
  }

  async function loadHistory(range, section) {
    try {
      const response = await fetch(`/statistics/history?range=${encodeURIComponent(range)}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('history unavailable');
      const samples = await response.json();
      if (!Array.isArray(samples)) throw new Error('invalid history response');
      drawCharts(samples, section);
    } catch (_) {
      drawCharts([], section);
      if (section) section.querySelectorAll('.chart-empty').forEach((empty) => { empty.hidden = false; });
    }
  }

  function connect() {
    if (document.hidden || stream) return;
    stream = new EventSource('/statistics/events');
    stream.addEventListener('metrics', (event) => {
      try { updateLive(JSON.parse(event.data)); } catch (_) { updateStatus('disconnected'); }
    });
    stream.addEventListener('auth-required', () => {
      stream.close();
      stream = null;
      statusLabel.textContent = 'Sign in again to view statistics';
      statusRoot.dataset.status = 'disconnected';
    });
    stream.onopen = () => updateStatus('live');
    stream.onerror = () => updateStatus('disconnected');
  }

  function disconnectForHiddenTab() {
    if (document.hidden) {
      if (stream) stream.close();
      stream = null;
      statusLabel.textContent = 'Paused while this tab is hidden';
      statusRoot.dataset.status = 'partial';
    } else {
      connect();
    }
  }

  hostRange.addEventListener('change', () => loadHistory(hostRange.value, document.querySelector('.host-metrics').parentElement));
  proxyRange.addEventListener('change', () => loadHistory(proxyRange.value, document.querySelector('.proxy-section')));
  document.addEventListener('visibilitychange', disconnectForHiddenTab);
  loadHistory(hostRange.value, document.querySelector('.host-metrics').parentElement);
  loadHistory(proxyRange.value, document.querySelector('.proxy-section'));
  connect();
})();
