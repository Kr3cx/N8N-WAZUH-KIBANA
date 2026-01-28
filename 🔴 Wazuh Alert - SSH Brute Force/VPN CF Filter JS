// n8n Code node (Run Once for Each Item)
const doc = $json;

// Ambil string untuk deteksi (VT + GeoJS + RouterJS)
// Sesuaikan kalau field kamu beda, tapi ini aman karena pakai fallback.
const vtOrg =
  doc.threatintel?.virustotal?.as_owner ||
  doc.threatintel?.virustotal?.as_org ||
  doc.threatintel?.virustotal?.whois ||
  "";

const geoOrg =
  doc.source?.geo?.isp ||
  doc.source?.geo?.org ||
  doc.source?.geo?.as_org ||
  "";

const asnText = `${vtOrg} ${geoOrg}`.toLowerCase();

// Heuristik: Cloudflare / WARP / CDN / proxy / vpn / hosting
const isCloudflare =
  asnText.includes("cloudflare") ||
  asnText.includes("warp");

const isVPNProxy =
  asnText.includes("vpn") ||
  asnText.includes("proxy") ||
  asnText.includes("tor") ||
  asnText.includes("datacenter") ||
  asnText.includes("hosting") ||
  asnText.includes("ovh") ||
  asnText.includes("digitalocean") ||
  asnText.includes("linode") ||
  asnText.includes("vultr");

// Flag untuk debugging di Kibana (opsional)
doc.network = doc.network || {};
doc.network.anonymous = Boolean(isCloudflare || isVPNProxy);
doc.network.anonymous_type = isCloudflare ? "cdn" : (isVPNProxy ? "proxy/vpn/hosting" : "none");

// Kalau VPN/Cloudflare → DROP item (tidak lanjut ke MAP)
if (doc.network.anonymous) {
  return []; // ini yang membuat "tidak masuk map"
}

// Kalau bukan → teruskan
return [{ json: doc }];
