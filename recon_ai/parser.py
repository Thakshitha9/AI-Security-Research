import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    scripts: list[str] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    hostname: str = ""
    state: str = ""
    os: str = ""
    ports: list[Port] = field(default_factory=list)


@dataclass
class ScanData:
    hosts: list[Host] = field(default_factory=list)
    scan_info: str = ""


def parse_nmap_xml(filepath: str) -> ScanData:
    tree = ET.parse(filepath)
    root = tree.getroot()

    scan_info = root.attrib.get("args", "")
    hosts = []

    for host_elem in root.findall("host"):
        # IP address
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        ip = addr_elem.attrib["addr"] if addr_elem is not None else "unknown"

        # Hostname
        hostname = ""
        hostnames_elem = host_elem.find("hostnames/hostname")
        if hostnames_elem is not None:
            hostname = hostnames_elem.attrib.get("name", "")

        # State
        status_elem = host_elem.find("status")
        state = status_elem.attrib.get("state", "") if status_elem is not None else ""

        # OS detection
        os_name = ""
        osmatch = host_elem.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.attrib.get("name", "")

        # Ports
        ports = []
        for port_elem in host_elem.findall("ports/port"):
            port_num = int(port_elem.attrib.get("portid", 0))
            protocol = port_elem.attrib.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            port_state = state_elem.attrib.get("state", "") if state_elem is not None else ""

            service_elem = port_elem.find("service")
            service = ""
            version = ""
            if service_elem is not None:
                service = service_elem.attrib.get("name", "")
                product = service_elem.attrib.get("product", "")
                ver = service_elem.attrib.get("version", "")
                version = f"{product} {ver}".strip()

            scripts = []
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.attrib.get("id", "")
                script_output = script_elem.attrib.get("output", "")
                scripts.append(f"{script_id}: {script_output}")

            ports.append(Port(
                number=port_num,
                protocol=protocol,
                state=port_state,
                service=service,
                version=version,
                scripts=scripts,
            ))

        hosts.append(Host(
            ip=ip, hostname=hostname, state=state, os=os_name, ports=ports,
        ))

    return ScanData(hosts=hosts, scan_info=scan_info)


def parse_nmap_text(text: str) -> ScanData:
    hosts = []
    current_host = None

    for line in text.split("\n"):
        line = line.strip()

        # Match host line
        host_match = re.match(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            hostname = host_match.group(1) or ""
            ip = host_match.group(2)
            current_host = Host(ip=ip, hostname=hostname, state="up")
            continue

        # Match port line
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)?", line
        )
        if port_match and current_host:
            current_host.ports.append(Port(
                number=int(port_match.group(1)),
                protocol=port_match.group(2),
                state=port_match.group(3),
                service=port_match.group(4),
                version=port_match.group(5).strip() if port_match.group(5) else "",
            ))

    if current_host:
        hosts.append(current_host)

    return ScanData(hosts=hosts)
