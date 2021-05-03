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
    const maxAlerts = core.getInput("maxAlerts");
    const max = parseInt(maxAlerts);
    var allResults = [];
    await Promise.all(repositories.map(async (repo) => {
      var results = await alerts(repo, token, max);
      allResults.push(results.data.repository);
    }));
    fs.writeFileSync(output, JSON.stringify(allResults));
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();