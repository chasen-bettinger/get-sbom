import os
import csv
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport


token_string = os.getenv("BOOST_API_TOKEN") or ""
token = f"ApiKey {token_string}"

if token_string == "":
    raise ValueError("Please provide a token")


def get_sbom():

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Prefer": "safe",
        "Content-Type": "application/json",
        "Authorization": token,
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-GPC": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }
    # Select your transport with a defined url endpoint
    transport = AIOHTTPTransport(
        url="https://api.boostsecurity.io/sbom-inventory/graphql", headers=headers
    )

    # Create a GraphQL client using the defined transport
    client = Client(transport=transport, fetch_schema_from_transport=True)

    query = gql(
        """

    query (
        $first: Int
        $after: String
        $last: Int
        $before: String
        $page: Int
        $search: String
        $orgName: String
        $projectName: String
        $labelName: String
        $withVulnerabilities: Boolean
        $packageTypes: [String!]
        $isFixable: Boolean
        $withoutTransitiveThrough: Boolean
        $analysisId: String
        $orderBy: [PackagesOrder!]
        $locatePackageId: String
        $licenses: [String!]
    ) {
        packages(
            first: $first
            after: $after
            last: $last
            before: $before
            page: $page
            filters: {
                search: $search
                asset: {
                    organizationName: $orgName
                    projectName: $projectName
                    assetLabel: $labelName
                }
                analysisId: $analysisId
                withVulnerabilities: $withVulnerabilities
                packageTypes: $packageTypes
                isFixable: $isFixable
                withoutTransitiveThrough: $withoutTransitiveThrough
                licenses: $licenses
            }
            orderBy: $orderBy
            locatePackageId: $locatePackageId
        ) {
            totalCount
            edges {
                node {
                    packageId
                    name
                    version
                    packageType
                    ecosystem
                    analysisCount
                    vulnerabilities {
                        originalId
                        vulnerabilityId
                        originalId
                        severity
                        source {
                            name
                            url
                        }
                        description
                        ratings {
                            source {
                                name
                                url
                            }
                            score
                            severity
                            method
                            justification
                            vector
                        }
                        advisories {
                            title
                            url
                        }
                    }
                    vulnerabilityCount {
                        critical
                        high
                        medium
                        low
                        info
                        none
                        unknown
                    }
                    analysisCount
                    transitiveThrough {
                        name
                        version
                    }
                    licenses {
                        expression
                    }
                    scorecard {
                        date
                        checks {
                            name
                            score
                            documentationDesc
                            documentationUrl
                            reason
                            details
                        }
                        overallScore
                    }
                    scorecardUrl
                }
                cursor
            }
            filters {
                packageTypes {
                    value
                }
                licenses {
                    value
                }
            }
            pageInfo {
                hasNextPage
                hasPreviousPage
                startCursor
                endCursor
            }
        }
    }

    """
    )
    params = {
        "first": 100,
        "search": "",
        "withVulnerabilities": False,
        "isFixable": False,
        "withoutTransitiveThrough": False,
        "licenses": [],
    }

    results = [["Package Name", "Version", "License", "Ecosystem"]]

    def paginate(page=None):
        if page != None:
            params["page"] = page
        result = client.execute(query, variable_values=params)
        r = result["packages"]["edges"]

        for e in r:
            n = e["node"]

            all_licenses = n["licenses"]
            all_licenses_formatted = []
            for l in all_licenses:
                license = l["expression"]
                all_licenses_formatted.append(license)
            licenses = ", ".join(all_licenses_formatted)

            p = {
                "package_name": n["name"],
                "license": licenses,
                "ecosystem": n["ecosystem"],
                "version": n["version"],
            }
            row = [p["package_name"], p["version"], p["license"], p["ecosystem"]]
            results.append(row)

        if result["packages"]["pageInfo"]["hasNextPage"]:

            if page == None:
                page = 2
            else:
                page = page + 1

            return paginate(page)

    paginate()
    return results


sbom_results = get_sbom()

with open("sbom.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerows(sbom_results)
