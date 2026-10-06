// Regression exceptions preserve non-pass evidence. They never confer certification.
export function selectPlans(value, available) {
  const selected = value.split(",");
  if (
    !selected.length ||
    new Set(selected).size !== selected.length ||
    selected.some((p) => !available.includes(p))
  ) {
    throw new Error(
      "Select a nonempty, unique list of known conformance plans",
    );
  }
  return selected;
}

export function selectModules(available, requested) {
  if (
    !Array.isArray(available) ||
    !available.length ||
    available.some((m) => typeof m !== "string" || !m) ||
    new Set(available).size !== available.length
  ) {
    throw new Error(
      "Conformance plan returned an empty, malformed or duplicate module list",
    );
  }
  if (requested === null) return available;
  if (
    !requested.length ||
    new Set(requested).size !== requested.length ||
    requested.some((m) => !available.includes(m))
  ) {
    throw new Error(
      "Selected conformance modules are empty, duplicate or unknown for this plan",
    );
  }
  return requested;
}

export function verdict(
  summary,
  { selected, policy = "strict", known = {}, modules = null },
) {
  const failures = [];
  const expected = [];
  const seen = new Set();
  const plans = new Set();
  let passed = 0;
  if (!["strict", "regression"].includes(policy))
    failures.push("Unknown verdict policy");
  if (!Array.isArray(summary) || !summary.length)
    return {
      ok: false,
      passed,
      expected,
      failures: ["Empty conformance evidence"],
    };
  for (const row of summary) {
    if (
      !row ||
      !selected.includes(row.plan) ||
      typeof row.module !== "string" ||
      !row.module ||
      typeof row.status !== "string" ||
      typeof row.result !== "string" ||
      (modules && !modules[row.plan]?.includes(row.module))
    ) {
      failures.push("Malformed or unexpected conformance evidence");
      continue;
    }
    const key = row.plan + ":" + row.module;
    if (seen.has(key)) failures.push("Duplicate module: " + key);
    seen.add(key);
    plans.add(row.plan);
    if (row.status === "FINISHED" && row.result === "PASSED") {
      passed++;
      continue;
    }
    const exception = known[row.plan]?.[row.module];
    if (
      policy === "regression" &&
      exception?.reason &&
      row.status === exception.status &&
      row.result === exception.result
    ) {
      expected.push({ ...row, reason: exception.reason });
    } else failures.push(key + ": " + row.status + "/" + row.result);
  }
  for (const plan of selected)
    if (!plans.has(plan))
      failures.push("No evidence for selected plan: " + plan);
  if (modules) {
    for (const [plan, expectedModules] of Object.entries(modules)) {
      for (const module of expectedModules) {
        if (!seen.has(plan + ":" + module))
          failures.push("Missing selected module: " + plan + ":" + module);
      }
    }
  }
  return { ok: failures.length === 0, passed, expected, failures };
}
