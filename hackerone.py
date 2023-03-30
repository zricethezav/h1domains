import requests
import json

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
        'domains': [],
        'with_bounty': [],
    }
    csv = [['handle', 'domain', 'eligible_for_bounty']]
    page = 1
    with requests.Session() as session:
        while True:
            r = session.get(query_url.format(page=page))
            page += 1
            if r.status_code != 200:
                break
            resp = json.loads(r.text)
            for program in resp['results']:
                r = session.get("https://hackerone.com{program}".format(
                    program=program['url']),
                    headers={'Accept': 'application/json'})
                if r.status_code != 200:
                    print('unable to retreive %s', program['name'])
                    continue

                resp = json.loads(r.text)
                print('policy scope ', resp['handle'])

                # new scope
                query = json.dumps({'query': policy_scope_query,
                                    'variables': {'handle': resp['handle']}})
                r = session.post("https://hackerone.com/graphql",
                                 data=query,
                                 headers={'content-type': 'application/json'})
                policy_scope_resp = json.loads(r.text)

                for e in policy_scope_resp['data']['team']['structured_scopes_search']['nodes']:
                    if (e['display_name'] == 'Domain' and e['eligible_for_submission']) or \
                    (e['eligible_for_submission'] and e['identifier'].startswith('*')):
                        identifier = e['identifier']
                        for i in identifier.split(','):
                            targets['domains'].append(i)
                            bounty = e['eligible_for_bounty']
                            if bounty is None:
                                bounty = False
                            if bounty is True:
                                targets['with_bounty'].append(i)
                            csv.append([resp['handle'], i, str(bounty)])

                # old scope
                query = json.dumps({'query': scope_query,
                                    'variables': {'handle': resp['handle']}})
                                    # 'variables': {'handle': 'malwarebytes'}})
                r = session.post("https://hackerone.com/graphql",
                                 data=query,
                                 headers={'content-type': 'application/json'})
                scope_resp = json.loads(r.text)
                for e in scope_resp['data']['team']['in_scope_assets']['edges']:
                    node = e['node']
                    if node['asset_type'] == 'Domain' or node['asset_identifier'].startswith('*') or node['asset_type'] == 'URL':
                        identifier = node['asset_identifier']
                        for i in identifier.split(','):
                            targets['domains'].append(i)
                            bounty = node['eligible_for_bounty']
                            if bounty is None:
                                bounty = False
                            if bounty is True:
                                targets['with_bounty'].append(i)
                            csv.append([resp['handle'], i, str(bounty)])
    return targets, csv


if __name__ == "__main__":
    targets, csv = hackerone_to_list()
    with open('domains.txt', 'w') as f:
        f.write('\n'.join(targets['domains']))
    with open('domains_with_bounties.txt', 'w') as f:
        f.write('\n'.join(targets['with_bounty']))
    with open('domains.csv', 'w') as f:
        f.write('\n'.join([','.join(e) for e in csv]))
