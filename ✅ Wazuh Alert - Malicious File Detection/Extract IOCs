

return items.map((item) => {
  const body = item.json.body ?? item.json; 
  const rule = body.rule ?? {};
  const agent = body.agent ?? {};
  const syscheck = body.syscheck ?? {};
  const audit = syscheck.audit ?? {};

  const md5 = syscheck.md5_after ?? null;
  const sha1 = syscheck.sha1_after ?? null;
  const sha256 = syscheck.sha256_after ?? null;
  const filePath = syscheck.path ?? null;

  const description = rule.description ?? "No description";
  const level = rule.level ?? null;
  const ruleId = rule.id ?? null;

  return {
    json: {
      type: "file_alert",
      rule_id: ruleId,
      level,
      description,

      file_path: filePath,
      event: syscheck.event ?? null,
      mode: syscheck.mode ?? null,

      md5,
      sha1,
      sha256,

      agent: agent.name ?? null,
      agent_id: agent.id ?? null,
      agent_ip: agent.ip ?? null,

      actor_login: audit.login_user?.name ?? null,
      actor_effective: audit.effective_user?.name ?? null,
      process: audit.process?.name ?? null,

      timestamp: body.timestamp ?? null,

 
      fullAlert: body,
    },
  };
});
