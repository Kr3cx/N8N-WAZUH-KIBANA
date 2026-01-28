/**
 * n8n Code node (Run Once for All Items)
 * Input: hasil Merge berupa 3 item (VT, Wazuh, GeoIP) dalam $input.all()
 * Output: 1 item enriched, hanya field penting untuk Kibana/Elasticsearch.
 */

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function toIso(ts) {
  if (!ts) return new Date().toISOString();
  const d = new Date(ts);
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

// Ambil semua item dari merge
const items = $input.all().map(i => i.json);

// Deteksi masing-masing payload
const vt = items.find(j => j?.data?.type === "ip_address") || null;
const ex = items.find(j => j?.timestamp && j?.rule && j?.agent) || null;

const geoRaw = items.find(j => typeof j?.stdout === "string") || null;
const geo = geoRaw ? (safeJsonParse(geoRaw.stdout) || null) : null;

// Primary IP (ambil dari Extract IOC kalau ada)
const srcip = ex?.source?.structured?.srcip ?? null;
const xff = ex?.source?.headers?.["x-forwarded-for"] ?? null;
const ipsExternal = ex?.source?.extracted?.ips_external ?? [];
const primaryIp =
  srcip || xff || ipsExternal?.[0] || ex?.source?.extracted?.ips?.[0] || geo?.query || vt?.data?.id || null;

// VT ringkas (yang penting)
const vtAttr = vt?.data?.attributes || {};
const vtStats = vtAttr?.last_analysis_stats || {};
const vtSummary = vt ? {
  id: vt?.data?.id,
  asn: vtAttr?.asn ?? null,
  as_owner: vtAttr?.as_owner ?? null,
  country: vtAttr?.country ?? null,
  reputation: vtAttr?.reputation ?? null,
  network: vtAttr?.network ?? null,
  last_analysis_date: vtAttr?.last_analysis_date
    ? new Date(vtAttr.last_analysis_date * 1000).toISOString()
    : null,
  stats: {
    malicious: vtStats?.malicious ?? null,
    suspicious: vtStats?.suspicious ?? null,
    harmless: vtStats?.harmless ?? null,
    undetected: vtStats?.undetected ?? null,
    timeout: vtStats?.timeout ?? null,
  },
  // whois panjang banget; simpan opsional (kalau mau dihapus, hapus baris ini)
  whois: vtAttr?.whois ?? null,
} : null;

// Geo penting untuk Kibana Maps
const geoPoint =
  (geo && typeof geo.lat === "number" && typeof geo.lon === "number")
    ? { lat: geo.lat, lon: geo.lon }
    : undefined;

// Output final: minimal + penting
const out = {
  "@timestamp": toIso(ex?.timestamp || new Date().toISOString()),
  event: { kind: "alert", dataset: "wazuh.enriched", module: "wazuh" },

  // Rule penting
  rule: ex ? {
    id: ex.rule.id,
    level: ex.rule.level,
    description: ex.rule.description,
    groups: ex.rule.groups || [],
    mitre: ex.rule.mitre || null,
  } : null,

  // Agent penting
  agent: ex ? {
    id: ex.agent.id,
    name: ex.agent.name,
    ip: ex.agent.ip,
  } : null,

  // Source + geo untuk Maps
  source: {
    ip: primaryIp,
    port: ex?.source?.extracted?.ports?.[0] ?? null,
    user: ex?.source?.extracted?.users?.[0] ?? null,
    geo: geo ? {
      country_name: geo.country,
      country_iso_code: geo.countryCode,
      region_name: geo.regionName,
      region_iso_code: geo.region,
      city_name: geo.city,
      timezone: geo.timezone,
      location: geoPoint, // <-- geo_point
    } : undefined,
  },

  // IOC list ringkas
  related: ex ? {
    ip: uniq(ex?.source?.extracted?.ips),
    hosts: uniq(ex?.source?.extracted?.hostnames),
    user: uniq(ex?.source?.extracted?.users),
  } : undefined,

  threatintel: vtSummary ? { virustotal: vtSummary } : undefined,

  wazuh: ex ? {
    manager: ex?.manager?.name ?? null,
    full_log: ex?.raw_hits?.full_log ?? null,
  } : undefined,

  debug: {
    found: { extract_ioc: !!ex, virustotal: !!vt, geoip: !!geo },
    input_items: items.length,
  },
};

// Rapikan: hapus field undefined/null besar yang nggak perlu
if (!out.source.geo) delete out.source.geo;
if (!out.related) delete out.related;
if (!out.threatintel) delete out.threatintel;
if (!out.wazuh) delete out.wazuh;

// Kalau ex/vt null, biar nggak ada object null
if (!out.rule) delete out.rule;
if (!out.agent) delete out.agent;

return [{ json: out }];
