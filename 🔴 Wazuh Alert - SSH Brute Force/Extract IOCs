// n8n Function node
// Input: items[0].json = object seperti contoh kamu
// Output: satu item berisi object IOC yang sudah diekstrak

function uniq(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

function findAll(regex, text) {
  const out = [];
  if (!text) return out;
  let m;
  while ((m = regex.exec(text)) !== null) {
    out.push(m[1] ?? m[0]);
  }
  return out;
}

function isPrivateIp(ip) {
  // simple private/local check
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip)
  );
}

const event = items?.[0]?.json?.body ?? {};
const headers = items?.[0]?.json?.headers ?? {};
const logs = [
  event.full_log || "",
  event.previous_output || "",
].join("\n");

// 1) IOC dari field terstruktur Wazuh
const srcip = event?.data?.srcip;
const srcuser = event?.data?.srcuser;
const agentIp = event?.agent?.ip;

// 2) IOC dari header (kadang ada x-forwarded-for)
const xff = headers["x-forwarded-for"] || headers["x-real-ip"];

// 3) IOC dari teks log (full_log + previous_output)
const ipsFromText = findAll(/\b((?:\d{1,3}\.){3}\d{1,3})\b/g, logs);

// port sshd: "... port 58359 ssh2"
const portsFromText = findAll(/\bport\s+(\d{1,5})\b/g, logs).map(p => Number(p));

// username sshd: "invalid user nawur" atau "for <user>"
const invalidUsers = findAll(/\binvalid user\s+([a-zA-Z0-9._-]+)\b/g, logs);
const forUsers = findAll(/\bfor\s+([a-zA-Z0-9._-]+)\b/g, logs);

const allIps = uniq([srcip, xff, agentIp, ...ipsFromText]);

// kategorikan IP external vs internal
const internalIps = allIps.filter(isPrivateIp);
const externalIps = allIps.filter(ip => !isPrivateIp(ip));

// 4) Build output IOC object
const ioc = {
  timestamp: event.timestamp,
  rule: {
    id: event?.rule?.id,
    level: event?.rule?.level,
    description: event?.rule?.description,
    groups: event?.rule?.groups || [],
    mitre: event?.rule?.mitre || {},
  },
  agent: event?.agent || {},
  manager: event?.manager || {},
  source: {
    structured: {
      srcip: srcip || null,
      srcuser: srcuser || null,
    },
    headers: {
      host: headers.host || null,
      "x-forwarded-for": xff || null,
    },
    extracted: {
      ips: allIps,
      ips_internal: internalIps,
      ips_external: externalIps,
      ports: uniq(portsFromText),
      users: uniq([srcuser, ...invalidUsers, ...forUsers]),
      hostnames: uniq([event?.predecoder?.hostname, headers.host]),
      programs: uniq([event?.predecoder?.program_name, event?.decoder?.name, event?.decoder?.parent]),
    }
  },
  raw_hits: {
    full_log: event.full_log || null,
    previous_output: event.previous_output || null,
  }
};

return [{ json: ioc }];
