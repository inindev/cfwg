#
# cfwg.py - cloudflare wireguard profile generator
#
#   copyright (C) 2024, John Clark <inindev@gmail.com>
#
#   https://github.com/inindev/cfwg
#

import argparse
import json
import locale
import os
import subprocess
import textwrap
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError


CF_API_VER   = 'v0'
CFCLIENT_VER = '2024.6.416.0'
CFCLIENT_URL = f'https://api.cloudflareclient.com/{CF_API_VER}'


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='cloudflare wireguard profile generator',
        epilog=textwrap.dedent('''\
            ----------------------------------
             jwt token generation:
               navigate to https://<team_domain>.cloudflareaccess.com/warp  (see settings->custom pages for team domain name)
               authenticate, then view source of the result page (cmd+opt+u) for the jwt token
               or use the following code in the web console (cmd+opt+j):
               console.log(document.querySelector("meta[http-equiv='refresh']").content.split("=")[2])
            ----------------------------------
        ''')
    )
    mylocale,_ = locale.getlocale()
    parser.add_argument('jwt_token', help='team json web token for the client session')
    parser.add_argument('--name', help='device name')
    parser.add_argument('--type', help='device type')
    parser.add_argument('--model', help='device model')
    parser.add_argument('--manf', help='device manufacturer')
    parser.add_argument('--os_ver', help='device os version')
    parser.add_argument('--serial', help='device serial number')
    parser.add_argument('--locale', default=mylocale, help=f'device locale ({mylocale})')
    parser.add_argument('--ipv6', default=False, action='store_true', help='include ipv6 entries in wireguard config')
    args = parser.parse_args()

    wg_prv_key = wg_private_key()
    wg_pub_key = wg_public_key(wg_prv_key)

    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'okhttp/3.12.1',
        'Accept': 'application/json',
        'CF-Client-Version': CFCLIENT_VER,
        'CF-Access-Jwt-Assertion': args.jwt_token,
    }

    data = {
        'key': wg_pub_key,
        'name': args.name,
        'install_id': None,
        'fcm_token': None,
        'referrer': None,
        'tos': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        'expired': None,
        'device_type': args.type,
        'manufacturer': args.manf,
        'model': args.model,
        'serial_number': args.serial,
        'os_version': args.os_ver,
        'locale': args.locale,
    }
    data = {k: v for k, v in data.items() if v}
    #print(json.dumps(data))

    response = make_request(f'{CFCLIENT_URL}/reg', headers, data)
    resp_data = json.loads(response)

    cf_config = resp_data['result']['config']
    wg_config = gen_wireguard_config(cf_config, wg_prv_key, wg_pub_key, args.ipv6)
    print(wg_config)


def gen_wireguard_config(cf_config, wg_private_key, wg_public_key, ipv6=False, wg_mtu=1280):
    address = cf_config['interface']['addresses']['v4']
    dns = '1.1.1.1, 1.0.0.1'
    allowed_ips = '0.0.0.0/0'
    if ipv6:
        address += f", {cf_config['interface']['addresses']['v6']}"
        dns += ', 2606:4700:4700::1111, 2606:4700:4700::1001'
        allowed_ips += ', ::/0'

    peer = cf_config['peers'][0]
    endpoint = peer['endpoint']
    ep_v4 = urlparse(f"//{endpoint['v4']}").hostname
    ep_v6 = urlparse(f"//{endpoint['v6']}").hostname
    ep_host = urlparse(f"//{endpoint['host']}").hostname

    wg_config = textwrap.dedent(f'''\
        [Interface]
        PrivateKey = {wg_private_key}
        #PublicKey = {wg_public_key}
        Address = {address}
        DNS = {dns}
        MTU = {wg_mtu}

        [Peer]
        PublicKey = {peer['public_key']}
        AllowedIPs = {allowed_ips}
        #PersistentKeepalive = 25
        # possible udp ports: 500, 1701, 2408, 4500
        Endpoint = {ep_v4}:2408
        #Endpoint = [{ep_v6}]:2408
        #Endpoint = {ep_host}:2408
    ''')

    return wg_config


def make_request(url, headers, data=None):
    if type(data) is dict:
        data = json.dumps(data).encode('utf-8')

    try:
        request = Request(url, headers=headers, data=data)
        with urlopen(request, timeout=8) as response:
            print(f'response.headers: {response.headers}');
            return response.read().decode('utf-8')
    except HTTPError as e:
        print(f'http error: {e.code} {e.reason}')
    except URLError as e:
        print(f'url error: {e.reason}')
    except TimeoutError:
        print('request timed out')


def wg_private_key():
    proc = subprocess.run(['wg', 'genkey'], env=os.environ, capture_output=True)
    return proc.stdout.decode('utf-8').rstrip('\n')

def wg_public_key(private_key):
    po = subprocess.Popen(['wg', 'pubkey'], stdin=subprocess.PIPE, env=os.environ, stdout=subprocess.PIPE)
    proc = po.communicate(input=private_key.encode('utf-8'))[0]
    return proc.decode('utf-8').rstrip('\n')

def wg_preshared_key():
    proc = subprocess.run(['wg', 'genpsk'], env=os.environ, capture_output=True)
    return proc.stdout.decode('utf-8').rstrip('\n')


if __name__ == '__main__':
    main()
