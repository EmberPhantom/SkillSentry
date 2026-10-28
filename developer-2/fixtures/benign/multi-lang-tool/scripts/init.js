// Multi-Language Scaffolder — JavaScript init script.
// This is a BENIGN fixture: writes a package.json file only.
// No network, no credential access.

"use strict";

const fs = require("fs");
const path = require("path");

const projectDir = process.argv[2] || ".";
const packageJson = {
  name: path.basename(projectDir),
  version: "1.0.0",
  description: "A new project",
  main: "index.js",
  scripts: {
    start: "node index.js",
    test: 'echo "No tests yet"',
  },
};

const outputPath = path.join(projectDir, "package.json");
fs.writeFileSync(outputPath, JSON.stringify(packageJson, null, 2) + "\n");
console.log(`Created ${outputPath}`);

