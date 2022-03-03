// const { graphql } = require("@octokit/graphql");
const { Octokit } = require("@octokit/core");


class HTTPResponseError extends Error {
  constructor(response, ...args) {
    super(`HTTP Error Response: ${response.status} ${response.statusText}`, ...args);
  }
}

const throwsNon200 = (response) => {
  if (response === undefined)
    throw new Error("Error response undefined");
  if (response.status >= 400)
    throw new HTTPResponseError(response);
  return response;
}

const getOwner = (repoUrl) => {
  const args = repoUrl.split('/');
  return args.length > 0 ? args[0] : '';
}

const getRepo = (repoUrl) => {
  const args = repoUrl.split('/');
  return args.length > 1 ? args[1] : '';
}

const getStates = (statesString) => {
  const args = statesString.split(',');
  return args;
}


const computeGrade = (data) => {
  if (data && data.repository && data.repository.vulnerabilityAlerts) {
    var grade = "A";
    const vulnerabilityAlerts = data.repository.vulnerabilityAlerts;
    if (vulnerabilityAlerts.totalCount > 0 && vulnerabilityAlerts.nodes.filter((node) => node.securityVulnerability.severity === 'CRITICAL').length > 0)
      grade = "E";
    else if (vulnerabilityAlerts.totalCount > 0 && vulnerabilityAlerts.nodes.filter((node) => node.securityVulnerability.severity === 'HIGH').length > 0)
      grade = "D";
    else if (vulnerabilityAlerts.totalCount > 0 && vulnerabilityAlerts.nodes.filter((node) => node.securityVulnerability.severity === 'MODERATE').length > 0)
      grade = "C";
    else if (vulnerabilityAlerts.totalCount > 0 && vulnerabilityAlerts.nodes.filter((node) => node.securityVulnerability.severity === 'LOW').length > 0)
      grade = "B";
    data.repository.grade = grade;
  }
  return data;
}

/**
 * Returns alerts from Github dependabot associated to a repo url
 *
 * @param {string} repoUrl The repository url as owner/repo
 * @param {string} token The token to authenticate to Github API
 * @param {number} maxAlerts The maximum alerts to fetch
 * @param {String} states The states to filter alerts
 *
 * @returns {GraphQlResponse}
 */
const alerts = (repoUrl, token, maxAlerts, states) => {
  console.warn(`Fetch first ${maxAlerts} in ${states} states Github dependabot alerts for ${repoUrl}`);
  const query = `query alerts($repo: String!, $owner: String!, $max: Int!, $states: [RepositoryVulnerabilityAlertState!]) {
    repository(name: $repo, owner: $owner) {
      url
      vulnerabilityAlerts(first: $max, states: $states) {
        totalCount
        nodes {
          dismissedAt
          createdAt
          securityVulnerability {
            severity
            package {
              name
            }
            advisory {
              identifiers {
                type
                value
              }
              references {
                url
              }
            }
          }
        }
      }
    }
  }`;
  const octokit = new Octokit({ auth: token });
  return octokit.request('POST /graphql', {
    query: query,
    variables: {
      owner: getOwner(repoUrl),
      repo: getRepo(repoUrl),
      max: maxAlerts,
      states: getStates(states)
    }
  }
  ).then(throwsNon200).then(response => computeGrade(response.data.data));
}

module.exports = alerts;