import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { verdict, selectPlans, selectModules } from "./verdict.mjs";

const pass = {
  plan: "basic",
  module: "login",
  status: "FINISHED",
  result: "PASSED",
};
const known = {
  basic: {
    unsigned: {
      status: "FINISHED",
      result: "SKIPPED",
      reason:
        "Unsigned tokens are refused; this is not passing certification evidence.",
    },
  },
};

test("strict mode accepts completed passes and rejects every non-pass", () => {
  assert.equal(verdict([pass], { selected: ["basic"] }).ok, true);
  for (const result of [
    "FAILED",
    "WARNING",
    "REVIEW",
    "SKIPPED",
    "NONE",
    "unknown",
  ]) {
    assert.equal(
      verdict([{ ...pass, result }], { selected: ["basic"] }).ok,
      false,
    );
  }
  assert.equal(
    verdict([{ ...pass, status: "DRIVER_ERROR" }], { selected: ["basic"] }).ok,
    false,
  );
  assert.equal(
    verdict([{ ...pass, status: "INTERRUPTED" }], { selected: ["basic"] }).ok,
    false,
  );
});

test("empty, missing-plan, duplicate and malformed evidence fail", () => {
  assert.equal(verdict([], { selected: ["basic"] }).ok, false);
  assert.equal(verdict([pass], { selected: ["basic", "refresh"] }).ok, false);
  assert.equal(verdict([pass, pass], { selected: ["basic"] }).ok, false);
  assert.equal(verdict([null], { selected: ["basic"] }).ok, false);
});

test("regression mode permits only exact documented known outcomes", () => {
  const skipped = { ...pass, module: "unsigned", result: "SKIPPED" };
  assert.equal(
    verdict([skipped], { selected: ["basic"], policy: "strict", known }).ok,
    false,
  );
  const result = verdict([skipped], {
    selected: ["basic"],
    policy: "regression",
    known,
  });
  assert.equal(result.ok, true);
  assert.equal(result.passed, 0);
  assert.equal(result.expected.length, 1);
  assert.equal(
    verdict([{ ...skipped, result: "FAILED" }], {
      selected: ["basic"],
      policy: "regression",
      known,
    }).ok,
    false,
  );
  assert.equal(
    verdict([skipped], { selected: ["basic"], policy: "regression" }).ok,
    false,
  );
});

test("invalid plans, unknown modules and empty selections fail before requests", () => {
  assert.throws(() => selectPlans("", ["basic"]));
  assert.throws(() => selectPlans("typo", ["basic"]));
  assert.throws(() => selectPlans("basic,basic", ["basic"]));
  assert.deepEqual(selectPlans("basic", ["basic"]), ["basic"]);
  assert.throws(() => selectModules([], null));
  assert.throws(() => selectModules(["login"], ["typo"]));
  assert.deepEqual(selectModules(["login", "refresh"], ["login"]), ["login"]);
});

test("retained evidence keeps third-party failure distinct from allowed skip and review", () => {
  const receipt = JSON.parse(
    fs.readFileSync(
      new URL("../../docs/evidence/conformance/summary.json", import.meta.url),
      "utf8",
    ),
  );
  const known = JSON.parse(
    fs.readFileSync(new URL("./known-outcomes.json", import.meta.url), "utf8"),
  ).known;
  const rows = receipt.summary;
  const supported = rows.filter(
    (r) => r.plan !== "oidcc-client-test-3rd-party-init-login-test-plan",
  );
  const selected = [...new Set(supported.map((r) => r.plan))];
  assert.equal(
    verdict(supported, { selected, policy: "strict", known }).ok,
    false,
  );
  const regression = verdict(supported, {
    selected,
    policy: "regression",
    known,
  });
  assert.equal(regression.ok, true);
  assert.equal(regression.expected.length, 6);
  assert.equal(
    verdict(rows, {
      selected: [
        ...selected,
        "oidcc-client-test-3rd-party-init-login-test-plan",
      ],
      policy: "regression",
      known,
    }).ok,
    false,
  );
});

test("every selected module must have exactly one verdict", () => {
  const modules = { basic: ["login", "rotation"] };
  assert.equal(verdict([pass], { selected: ["basic"], modules }).ok, false);
  assert.equal(
    verdict([pass, { ...pass, module: "rotation" }], {
      selected: ["basic"],
      modules,
    }).ok,
    true,
  );
  assert.equal(
    verdict(
      [
        pass,
        { ...pass, module: "rotation" },
        { ...pass, module: "unexpected" },
      ],
      { selected: ["basic"], modules },
    ).ok,
    false,
  );
});
