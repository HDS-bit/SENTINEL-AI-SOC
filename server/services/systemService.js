import os from 'os';

let lastCpus = os.cpus();
let lastCpuMeasureTime = Date.now();
let cachedCpuUsage = 15;

/**
 * Calculate dynamic CPU usage percentage across all cores
 */
export function getCpuUsage() {
  const currentCpus = os.cpus();
  const currentTime = Date.now();
  
  if (currentTime - lastCpuMeasureTime < 800) {
    return cachedCpuUsage;
  }

  let totalIdle = 0;
  let totalTick = 0;

  for (let i = 0; i < currentCpus.length; i++) {
    const prevCore = lastCpus[i] || currentCpus[i];
    const currCore = currentCpus[i];

    const idleDelta = currCore.times.idle - prevCore.times.idle;
    let totalDelta = 0;

    for (const type of Object.keys(currCore.times)) {
      totalDelta += currCore.times[type] - prevCore.times[type];
    }

    totalIdle += idleDelta;
    totalTick += totalDelta;
  }

  lastCpus = currentCpus;
  lastCpuMeasureTime = currentTime;

  if (totalTick === 0) return cachedCpuUsage;

  const usage = Math.round((1 - (totalIdle / totalTick)) * 100);
  cachedCpuUsage = Math.max(1, Math.min(100, isNaN(usage) ? 12 : usage));
  return cachedCpuUsage;
}

/**
 * Get comprehensive real-time system metrics
 */
export function getSystemMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = Math.round((usedMem / totalMem) * 100);
  
  const processMem = process.memoryUsage();
  const cpuUsage = getCpuUsage();
  const loadAvg = os.loadavg();
  const uptime = os.uptime();

  return {
    timestamp: new Date().toISOString(),
    status: 'OPERATIONAL',
    cpu: {
      usagePercent: cpuUsage,
      cores: os.cpus().length,
      model: os.cpus()[0]?.model || 'Generic Server CPU',
      speedMHz: os.cpus()[0]?.speed || 2400
    },
    memory: {
      totalBytes: totalMem,
      totalMB: Math.round(totalMem / (1024 * 1024)),
      usedMB: Math.round(usedMem / (1024 * 1024)),
      freeMB: Math.round(freeMem / (1024 * 1024)),
      usedPercent: memUsagePercent,
      processHeapUsedMB: Math.round(processMem.heapUsed / (1024 * 1024)),
      processRssMB: Math.round(processMem.rss / (1024 * 1024))
    },
    loadAverage: {
      '1m': parseFloat(loadAvg[0].toFixed(2)),
      '5m': parseFloat(loadAvg[1].toFixed(2)),
      '15m': parseFloat(loadAvg[2].toFixed(2))
    },
    uptimeSeconds: uptime,
    uptimeFormatted: formatUptime(uptime)
  };
}

/**
 * Get server host platform & network information
 */
export function getServerInfo() {
  const netInterfaces = os.networkInterfaces();
  const activeAddresses = [];

  for (const name of Object.keys(netInterfaces)) {
    for (const net of netInterfaces[name]) {
      if (!net.internal && net.family === 'IPv4') {
        activeAddresses.push({ interface: name, address: net.address, netmask: net.netmask });
      }
    }
  }

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    type: os.type(),
    arch: os.arch(),
    nodeVersion: process.version,
    activeIpv4: activeAddresses,
    primaryIP: activeAddresses[0]?.address || '127.0.0.1',
    processUptimeSeconds: Math.round(process.uptime()),
    isContainerized: isRunningInContainer()
  };
}

function isRunningInContainer() {
  return Boolean(process.env.DOCKER_CONTAINER || process.env.KUBERNETES_SERVICE_HOST);
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / (3600 * 24));
  const h = Math.floor((seconds % (3600 * 24)) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);

  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}
