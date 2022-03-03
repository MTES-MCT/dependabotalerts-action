const fs = require("fs");
const core = require("@actions/core");

const alerts = require("./alerts");

function maxGrade(gradesArray) {
  const grades = new Map();
  grades.set("F", 6);
  grades.set("E", 5);
  grades.set("D", 4);
  grades.set("C", 3);
  grades.set("B", 2);
  grades.set("A", 1);
  const orders = new Map();
  orders.set(6, "F");
  orders.set(5, "E");
  orders.set(4, "D");
  orders.set(3, "C");
  orders.set(2, "B");
  orders.set(1, "A");
  return orders.get(Math.max(...gradesArray.map((grade) => grades.get(grade))));
}

function sumRepositoriesAlerts(repositories) {
  var sum = {};
  sum.totalCount = repositories
    .filter(Boolean)
    .map((repository) => repository.vulnerabilityAlerts.totalCount)
    .reduce((prev, curr) => prev + curr, 0);
  const grades = repositories
    .filter(Boolean)
    .map((repository) => repository.grade);
  sum.grade = maxGrade(grades);
  sum.repositories = repositories;
  return sum;
}

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
    const states= core.getInput("states");
    var repositoriesResults = [];
    await Promise.all(repositories.map(async (repo) => {
      var results = await alerts(repo, token, max, states);
      repositoriesResults.push(results.repository);
    }));
    fs.writeFileSync(output, JSON.stringify(sumRepositoriesAlerts(repositoriesResults)));
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();