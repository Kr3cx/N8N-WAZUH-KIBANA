return items.map((item, i) => {
  const vt = item.json; // response VirusTotal
  const ioc = $item(i).$node["Extract IOCs"].json; // data IOC dari Wazuh

  // Ambil sha256 prioritas: dari IOC dulu, baru fallback ke vt/body
  const sha = (ioc.sha256 ?? vt.sha256 ?? vt.body?.syscheck?.sha256_after ?? "").trim();

  // --- CASE: NOT FOUND / ERROR ---
  if (!vt.data?.attributes) {
    return {
      json: {
        // ✅ tetap bawa IOC supaya WA bisa ambil file_path, agent, dll
        ...ioc,

        // ✅ hasil routing
        route: "not_found",
        vt_status: "not_found",
        status: "NotFound",

        // ✅ VT fields konsisten
        sha256: sha || null,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        tags: [],
        reputation: null,
        magic: null,
        meaningful_name: null,
        vt_link: sha ? `https://www.virustotal.com/gui/file/${sha}` : null, // GUI link lebih enak
        vt_api_link: null,

        summary_text: sha
          ? `SHA256: ${sha}\nStatus: NotFound (belum ada di VirusTotal)`
          : "Status: sha256 kosong",
      },
    };
  }

  // --- CASE: FOUND ---
  const attr = vt.data.attributes;
  const stats = attr.last_analysis_stats ?? {};
  const sha256 = (attr.sha256 ?? vt.data.id ?? sha ?? null);

  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  const harmless = Number(stats.harmless ?? 0);
  const undetected = Number(stats.undetected ?? 0);

  let status = "Safe";
  if (malicious > 0) status = "Malicious";
  else if (suspicious > 0) status = "Suspicious";

  // Routing sesuai requirement kamu
  // 1) not_found: stop
  // 2) safe: gmail only
  // 3) malicious: gmail + incident + WA
  const route = malicious > 0 ? "malicious" : "safe";

  return {
    json: {
      // ✅ tetap bawa IOC
      ...ioc,

      // ✅ VT result + routing
      route,
      vt_status: "found",
      status,
      sha256,

      malicious,
      suspicious,
      harmless,
      undetected,

      tags: attr.tags ?? [],
      reputation: attr.reputation ?? null,
      magic: attr.magic ?? null,
      meaningful_name: attr.meaningful_name ?? null,

      // ✅ dua link: GUI (buat manusia) + API (buat mesin)
      vt_link: sha256 ? `https://www.virustotal.com/gui/file/${sha256}` : null,
      vt_api_link: vt.data?.links?.self ?? null,

      summary_text:
        `SHA256: ${sha256}\n` +
        `Status: ${status}\n` +
        `Malicious: ${malicious}\nSuspicious: ${suspicious}\nHarmless: ${harmless}\nUndetected: ${undetected}`,
    },
  };
});
