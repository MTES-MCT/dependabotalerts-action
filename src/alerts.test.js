const nock = require("nock");

const alerts = require("./alerts");

describe("fetch dependabot alerts from a Github repository", () => {
  beforeEach(() => {
    nock.disableNetConnect();
  });

  test("should return alerts", async () => {
    const dependatBotMock = {
      data: {
        repository: {
          url: "https://github.com/octocat/hello-world",
          vulnerabilityAlerts: {
            totalCount: 1,
            nodes: [
              {
                dismissedAt: null,
                createdAt: "2021-03-20T19:17:10Z",
                securityVulnerability: {
                  severity: "HIGH",
                  package: {
                    name: "is-svg",
                  },
                  advisory: {
                    identifiers: [
                      {
                        type: "GHSA",
                        value: "GHSA-7r28-3m3f-r2pr",
                      },
                      {
                        type: "CVE",
                        value: "CVE-2021-28092",
                      },
                    ],
                    references: [
                      {
                        url: "https://nvd.nist.gov/vuln/detail/CVE-2021-28092",
                      },
                      {
                        url:
                          "https://github.com/advisories/GHSA-7r28-3m3f-r2pr",
                      },
                    ],
                  },
                },
              },
            ],
          },
        },
      },
    };
    nock("https://api.github.com", {
      reqheaders: {
        authorization: "token test-token",
      },
    })
      .post("/graphql")
      .reply(200, dependatBotMock);

    const results = await alerts(["octocat/hello-world"], "test-token");
    expect(results).toEqual([dependatBotMock.data.repository]);
  });

  test("should return error bad credentials", async () => {
    const dependatBotMock = {
      message: "Bad credentials",
      documentation_url: "https://docs.github.com/graphql",
    };
    nock("https://api.github.com", {
      reqheaders: {
        authorization: "token wrong-token",
      },
    })
      .post("/graphql")
      .reply(200, dependatBotMock);

    await alerts(["octocat/hello-world"], "wrong-token")
      .then(() => {
        throw new Error("This should not succeed");
      })
      .catch((e) => {
        expect(e.message).toEqual("Bad credentials");
      });
  });

  test("should return error on API error", async () => {
    const expectedJson = [];
    nock("https://api.github.com", {
      reqheaders: {
        authorization: "token test-token",
      },
    })
      .post("/graphql")
      .reply(200, {
        data: { repository: null },
        errors: [{ message: "interesting error" }],
      });
    await alerts(["octocat/hello-world"], "test-token")
      .then(() => {
        throw new Error("This should not succeed");
      })
      .catch((e) => {
        expect(e.message).toEqual("interesting error");
      });
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });
});
