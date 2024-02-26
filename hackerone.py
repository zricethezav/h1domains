import requests
import re
import json
import itertools

query_url = "https://hackerone.com/programs/search?query=type:hackerone&sort=published_at:descending&page={page}"

policy_scope_query = """
query PolicySearchStructuredScopesQuery($handle: String!) {
  team(handle: $handle) {
    structured_scopes_search {
      nodes {
        ... on StructuredScopeDocument {
          identifier
          eligible_for_bounty
          eligible_for_submission
          display_name
          instruction
        }
      }
    }
  }
}
"""

scope_query = """
query TeamAssets($handle: String!) {
  team(handle: $handle) {
    in_scope_assets: structured_scopes(
      archived: false
      eligible_for_submission: true
    ) {
      edges {
        node {
          asset_identifier
          asset_type
          eligible_for_bounty
        }
      }
    }
  }
}
"""


def hackerone_to_list():
    targets = {
        "domains": [],
        "with_bounty": [],
        "source_code": [],
        "source_code_with_bounty": [],
    }
    csv = [["handle", "domain", "eligible_for_bounty"]]
    csv_source_code = [["handle", "source_code", "eligible_for_bounty"]]
    page = 1
    with requests.Session() as session:
        while True:
            r = session.get(query_url.format(page=page))
            page += 1
            if r.status_code != 200:
                break
            resp = json.loads(r.text)
            for program in resp["results"]:
                r = session.get(
                    "https://hackerone.com{program}".format(program=program["url"]),
                    headers={"Accept": "application/json"},
                )
                if r.status_code != 200:
                    print("unable to retreive %s", program["name"])
                    continue

                resp = json.loads(r.text)

                # new scope
                query = json.dumps(
                    {
                        "query": policy_scope_query,
                        "variables": {"handle": resp["handle"]},
                    }
                )
                r = session.post(
                    "https://hackerone.com/graphql",
                    data=query,
                    headers={"content-type": "application/json"},
                )
                policy_scope_resp = json.loads(r.text)

                for e in policy_scope_resp["data"]["team"]["structured_scopes_search"][
                    "nodes"
                ]:
                    if (
                        e["display_name"] == "Domain" and e["eligible_for_submission"]
                    ) or (
                        e["eligible_for_submission"] and e["identifier"].startswith("*")
                    ):
                        identifier = e["identifier"]
                        for i in identifier.split(","):
                            if i in targets["domains"]:
                                continue
                            targets["domains"].append(i)
                            bounty = e["eligible_for_bounty"]
                            if bounty is None:
                                bounty = False
                            if bounty is True:
                                targets["with_bounty"].append(i)
                            csv.append([resp["handle"], i, str(bounty)])
                    if (
                        e["display_name"] == "SourceCode"
                        and e["eligible_for_submission"]
                    ):
                        identifier = e["identifier"]
                        for id in identifier.split(","):
                            if (
                                id.startswith("https://")
                                or id.startswith("http://")
                                or id.startswith("git")
                                or id.startswith("www")
                                or re.match(r".*\/.*", id)
                            ):
                                if id.startswith("git") or id.startswith("www"):
                                    id = "https://" + id
                                if not id.startswith("http"):
                                    id = "https://github.com/" + id
                                if id in targets["source_code"]:
                                    continue
                                targets["source_code"].append(id)
                                bounty = e["eligible_for_bounty"]
                                if bounty is None:
                                    bounty = False
                                if bounty is True:
                                    targets["source_code_with_bounty"].append(id)
                                csv_source_code.append(
                                    [resp["handle"], id, str(bounty)]
                                )

                # old scope
                query = json.dumps(
                    {"query": scope_query, "variables": {"handle": resp["handle"]}}
                )
                # 'variables': {'handle': 'malwarebytes'}})
                r = session.post(
                    "https://hackerone.com/graphql",
                    data=query,
                    headers={"content-type": "application/json"},
                )
                scope_resp = json.loads(r.text)
                for e in scope_resp["data"]["team"]["in_scope_assets"]["edges"]:
                    node = e["node"]
                    if (
                        node["asset_type"] == "Domain"
                        or node["asset_identifier"].startswith("*")
                        or node["asset_type"] == "URL"
                    ):
                        identifier = node["asset_identifier"]
                        for i in identifier.split(","):
                            targets["domains"].append(i)
                            bounty = node["eligible_for_bounty"]
                            if bounty is None:
                                bounty = False
                            if bounty is True:
                                targets["with_bounty"].append(i)
                            csv.append([resp["handle"], i, str(bounty)])
                    if node["asset_type"] == "SOURCE_CODE":
                        identifier = node["asset_identifier"]
                        for id in identifier.split(","):
                            if (
                                id.startswith("https://")
                                or id.startswith("http://")
                                or id.startswith("git")
                                or id.startswith("www")
                                or re.match(r".*\/.*", id)
                            ):
                                if id.startswith("git") or id.startswith("www"):
                                    id = "https://" + id
                                if not id.startswith("http"):
                                    id = "https://github.com/" + id
                                if id in targets["source_code"]:
                                    continue
                                targets["source_code"].append(id)
                                bounty = node["eligible_for_bounty"]
                                if bounty is None:
                                    bounty = False
                                if bounty is True:
                                    targets["source_code_with_bounty"].append(id)
                                csv_source_code.append(
                                    [resp["handle"], id, str(bounty)]
                                )

    # dedupe
    targets["domains"] = list(set(targets["domains"]))
    targets["with_bounty"] = list(set(targets["with_bounty"]))
    targets["source_code"] = list(set(targets["source_code"]))
    targets["source_code_with_bounty"] = list(set(targets["source_code_with_bounty"]))

    return targets, csv, csv_source_code


if __name__ == "__main__":
    targets, csv, csv_source_code = hackerone_to_list()
    with open("domains.txt", "w") as f:
        f.write("\n".join(targets["domains"]))
    with open("domains_with_bounties.txt", "w") as f:
        f.write("\n".join(targets["with_bounty"]))
    with open("domains.csv", "w") as f:
        f.write("\n".join([",".join(e) for e in csv]))
    with open("source_code.csv", "w") as f:
        f.write("\n".join([",".join(e) for e in csv_source_code]))
    with open("source_code.txt", "w") as f:
        f.write("\n".join(targets["source_code"]))
    with open("source_code_with_bounties.txt", "w") as f:
        f.write("\n".join(targets["source_code_with_bounty"]))
