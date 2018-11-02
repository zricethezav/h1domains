import requests
import json

query_url = "https://hackerone.com/programs/search?query=type:hackerone&sort=published_at:descending&page={page}"

scope_query = """
    query($handle: String!, $after: String) {
      team(handle: $handle) {
        structured_scopes(first: 100, after: $after) {
          edges {
            node {
              asset_identifier,
              asset_type,
              eligible_for_bounty,
              max_severity,
            }
          }
        }
      }
    }
"""


def hackerone_to_list():
    domains = []
    open_scope_domains = []
    bounty_domains = []
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
                    print 'unable to retreive %s' % program['name']
                    continue

                resp = json.loads(r.text)
                query = json.dumps({'query': scope_query,
                                    'variables': {'after': '50',
                                                  'handle': resp['handle']}})
                r = session.post("https://hackerone.com/graphql",
                                 data=query,
                                 headers={'content-type': 'application/json'})
                scope_resp = json.loads(r.text)
                print resp['handle']
                for e in scope_resp['data']['team']['structured_scopes']['edges']:
                    if e['node']['asset_type'] == 'URL' and e['node']['max_severity']  != 'none':
                        domain = e['node']['asset_identifier']
                        if domain[0] == '*':
                            open_scope_domains.append(domain[2:])
                        if e['node']['eligible_for_bounty']:
                            bounty_domains.append(domain)
                        domains.append(domain)
    return domains, open_scope_domains, bounty_domains


if __name__ == "__main__":
    domains, open_scope_domains, bounty_domains = hackerone_to_list()
    with open('domains.txt', 'w') as f:
        f.write('\n'.join(domains))
    with open('domains_open.txt', 'w') as f:
        f.write('\n'.join(open_scope_domains))
    with open('domains_bounty.txt', 'w') as f:
        f.write('\n'.join(bounty_domains))
