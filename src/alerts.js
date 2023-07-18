// const { graphql } = require("@octokit/graphql");
const { Octokit } = require("@octokit/core");

class HTTPResponseError extends Error {
  constructor(response, ...args) {
    super(
      `HTTP Error Response: ${response.status} ${response.statusText}`,
      ...args
    );
  }
}

const throwsNon200 = (response) => {
  if (response === undefined) throw new Error("Error response undefined");
  if (response.status >= 400) throw new HTTPResponseError(response);
  return response;
};

const getOwner = (repoUrl) => {
  const args = repoUrl.split("/");
  return args.length > 0 ? args[0] : "";
};

const getRepo = (repoUrl) => {
  const args = repoUrl.split("/");
  return args.length > 1 ? args[1] : "";
};

/**
 * Returns alerts from Github dependabot associated to a repo url
 *
 * @param {string} repoUrl The repository url as owner/repo
 * @param {string} token The token to authenticate to Github API
 *
 * @returns {GraphQlResponse}
 */
const alerts = (repoUrl, token) => {
  console.warn(`Fetch Gihub dependabot alerts for ${repoUrl}`);
  const query = `query alerts($repo: String!, $owner: String!) {
    repository(name: $repo, owner: $owner) {
      url
      vulnerabilityAlerts(first: 100, states: OPEN) {
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
    .then((response) => response.data);
};

module.exports = alerts;
