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
            }
          }
        }
      }
    }
"""


def hackerone_to_list():
    domains = []
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
                    if e['node']['asset_type'] == 'URL':
                        domains.append(e['node']['asset_identifier'])

    return domains


if __name__ == "__main__":
    domains = hackerone_to_list()
    with open('domains.txt', 'w') as f:
        f.write('\n'.join(domains))
