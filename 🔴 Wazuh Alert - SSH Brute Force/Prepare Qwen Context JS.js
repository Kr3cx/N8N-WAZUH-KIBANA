// Ambil semua item dari node Merge
const items = $items("Merge");

// --- Pisahkan sumber ---
const vtItem = items.find(i => i.json?.data?.attributes);
const wazuhItem = items.find(i => i.json?.agent);

const vt = vtItem?.json?.data?.attributes || {};
const rdap = vt.rdap || {};
const wazuh = wazuhItem?.json || {};
const extracted = wazuh.source?.extracted || {};

// === ATTACKER ===
const attackerIp =
  vtItem?.json?.data?.id ||
  extracted.ips_external?.[0] ||
  extracted.ips?.[0] ||
  "unknown";

// === ISP & ASN (MURNI VT) ===
const isp = vt.as_owner || "unknown";
const asn = vt.asn || "unknown";
const country = vt.country || rdap.country || "unknown";

// === CLOUD FLAG (MURNI VT, NO KARANG) ===
const isCloud =
  (vt.tags || []).some(t =>
    ["hosting", "cdn", "datacenter"].includes(t)
  ) ||
  rdap.type === "ASSIGNED PA";

// === TARGET ===
const targetUser = extracted.users?.[0] || "unknown";

return [{
  json: {
    attacker: {
      ip: attackerIp,
      isp,
      asn,
      country,
      is_cloud_provider: isCloud
    },

    target: {
      host: wazuh.agent?.name || "unknown",
      host_ip: wazuh.agent?.ip || "unknown",
      agent_id: wazuh.agent?.id || "unknown",
      user: targetUser,
      is_privileged: ["root", "admin", "jenkins"].includes(targetUser)
    },

    attack: {
      service: "ssh",
      technique: wazuh.rule?.mitre?.technique?.[0] || "Brute Force",
      tactic: wazuh.rule?.mitre?.tactic?.[0] || "Credential Access",
      severity: wazuh.rule?.level ?? 0
    },

    reputation: {
      vt_malicious: vt.last_analysis_stats?.malicious ?? 0,
      vt_suspicious: vt.last_analysis_stats?.suspicious ?? 0,
      vt_reputation: vt.reputation ?? 0
    }
  }
}];
