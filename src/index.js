const fs = require("fs");
const core = require("@actions/core");

const alerts = require("./alerts");

async function run() {
  try {
    const repositoriesString = core.getInput("repositories");
    const repositories = repositoriesString.split(',');
    core.info(`Repositories JSON as ${JSON.stringify(repositories)} ...`);
    const token = core.getInput("token");
    core.setSecret(token);
    const output = core.getInput("output");
    const allResults = await alerts(repositories, token)
    fs.writeFileSync(output, JSON.stringify(allResults));
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();