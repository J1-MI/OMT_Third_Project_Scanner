#!/usr/bin/env python3
# usage: python scripts/nmap_xml_to_json.py <input.xml> <output.json>
import sys, xml.etree.ElementTree as ET, json
from pathlib import Path

def parse_nmap_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()
    ns = ''  # nmap XML v.. no namespace handling here
    results = []
    for host in root.findall('host'):
        # find ip
        addr = None
        for a in host.findall('address'):
            if a.get('addrtype') == 'ipv4' or a.get('addrtype') == 'ipv6':
                addr = a.get('addr')
                break
        if not addr:
            continue
        ports = host.find('ports')
        if ports is None:
            continue
        for p in ports.findall('port'):
            portid = int(p.get('portid'))
            state = p.find('state').get('state') if p.find('state') is not None else 'unknown'
            svc = p.find('service')
            banner = ''
            if svc is not None:
                name = svc.get('name') or ''
                prod = svc.get('product') or ''
                ver = svc.get('version') or ''
                extr = " ".join(filter(None, [name, prod, ver]))
                banner = extr
            results.append({
                "target": addr,
                "port": portid,
                "state": state,
                "banner": banner
            })
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: nmap_xml_to_json.py input.xml output.json")
        sys.exit(1)
    inp = Path(sys.argv[1])
    out = Path(sys.argv[2])
    data = parse_nmap_xml(inp)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2))
    print("Wrote", out)
