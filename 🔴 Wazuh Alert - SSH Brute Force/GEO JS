/**
 * Geo JS (n8n Code node)
 * Input: { stdout: "{\"status\":\"success\",...}" } dari node Geo IP
 * Output: object rapi + geo_point untuk Kibana Maps
 */

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

const item = $input.first().json;

// Parse stdout JSON
const geo = (typeof item.stdout === "string") ? safeJsonParse(item.stdout) : null;

if (!geo || geo.status !== "success") {
  // kalau gagal, tetap return debug biar ketahuan
  return [{
    json: {
      ok: false,
      error: "GeoIP stdout not parsable or status not success",
      raw: item,
    }
  }];
}

const out = {
  ok: true,
  ip: geo.query ?? null,

  country_name: geo.country ?? null,
  country_iso_code: geo.countryCode ?? null,

  region_name: geo.regionName ?? null,
  region_iso_code: geo.region ?? null,

  city_name: geo.city ?? null,
  timezone: geo.timezone ?? null,
  zip: geo.zip ?? null,

  asn: (typeof geo.as === "string" ? geo.as.split(" ")[0].replace(/^AS/i, "") : null), // "AS58381 ..." -> "58381"
  as_org: geo.as ?? null,

  isp: geo.isp ?? null,
  org: geo.org ?? null,

  // Kibana Maps butuh geo_point
  location: (typeof geo.lat === "number" && typeof geo.lon === "number")
    ? { lat: geo.lat, lon: geo.lon }
    : null,
};

// rapihin: hapus field null / kosong
for (const k of Object.keys(out)) {
  if (out[k] === "" || out[k] === null) delete out[k];
}

return [{ json: out }];
