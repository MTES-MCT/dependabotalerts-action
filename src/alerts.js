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
};

const throwsErrors = (response) => {
  if (response.data.errors && response.data.errors.length)
    throw new Error(response.data.errors[0].message);
  if (response.data.message === "Bad credentials")
    throw new Error(response.data.message);
  return response;
};

const getOwner = (repoUrl) => {
  const args = repoUrl.split('/');
  return args.length > 0 ? args[0] : '';
}

const getRepo = (repoUrl) => {
  const args = repoUrl.split('/');
  return args.length > 1 ? args[1] : '';

}

/**
 * Returns alerts from Github dependabot associated to a repo url
 *
 * @param {string} repoUrl The repository url as owner/repo
 * @param {string} token The token to authenticate to Github API
 *
 * @returns {GraphQlResponse}
 */
const repoAlerts = (repoUrl, token) => {
  console.warn(`Fetch Gihub dependabot alerts for ${repoUrl}`);
  const query = `query alerts($repo: String!, $owner: String!) {
    repository(name: $repo, owner: $owner) {
      url
      vulnerabilityAlerts(first: 10) {
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
  return octokit
    .request("POST /graphql", {
      query: query,
      variables: {
        owner: getOwner(repoUrl),
        repo: getRepo(repoUrl),
      },
    })
    .then(throwsNon200)
    .then(throwsErrors)
    .then((response) => response.data);
};

const alerts = async (repositories, token) => {
  const allResults = []
  await Promise.all(repositories.map(async repo => {
    const results = await repoAlerts(repo, token);
    if (results.data && results.data.repository) {
      allResults.push(results.data.repository);
    }
  }))
  return allResults;
};

module.exports = alerts;
