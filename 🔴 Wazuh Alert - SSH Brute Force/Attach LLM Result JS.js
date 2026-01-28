// Parse hasil LLM
let llm;
try {
  llm = JSON.parse($json.content);
} catch {
  llm = {
    verdict: "Unknown",
    confidence: "Low",
    recommended_action: "Monitor",
    reasoning: "Failed to parse LLM output"
  };
}

// Ambil CONTEXT ASLI dari node sebelumnya
const context = $node["Prepare Qwen Context JS"].json;

// Gabungkan context + analisis LLM
return [{
  json: {
    ...context,
    analysis: llm
  }
}];
