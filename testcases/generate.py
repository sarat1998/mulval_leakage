import sys
import time
from random import seed, random, randint


max_subnets = 10 # Max. no. of subnets in network
internet_prob = 0.1 # Probability of host being connected to the internet
root_prob = 0.30 # Probability of user having root privileges
victim_prob = 0.05 # Probability of user being incompetent
local_app_prob = 0.7 # Probability of being a local application
server_client_ratio = 0.15 # Ratio of no. of server programs to client programs
vuln_prob = 0.1 # Probability of application having a vulnerability
max_vulns_host = 3 # Max. no. of vulnerabilities per host
high_prob = 0.7 # Probability of vulnerability having high access complexity
medium_prob = 0.2 # Probability of vulnerability having medium access complexity
low_prob = 0.1 # Probability of vulnerability having low access complexity


def main():
    if len(sys.argv) == 3:
        output_path, num_hosts = sys.argv[1], int(sys.argv[2])
        seed(time.time())
        rules = '''
                    attackerLocated(internet).
                    attackGoal(execCode(_, _)).
                    hacl(X, Y, _, _):-
                        inSubnet(X, S),
                        inSubnet(Y, S).
                    isClient(clientApplication).
                '''

        num_subnets = randint(1, min(max_subnets, num_hosts))
        host_partition = {}
        num_hosts_left = num_hosts
        for subnet in range(1, num_subnets + 1):
            num_subnet_hosts = randint(0, num_hosts_left)
            host_partition[subnet] = num_subnet_hosts
            num_hosts_left -= num_subnet_hosts
        host_partition[next(iter(host_partition.keys()))] += num_hosts_left

        for subnet, num_subnet_hosts in host_partition.items():
            subnet_id = 'subnet{subnet}'.format(subnet=subnet)
            for host in range(1, num_subnet_hosts + 1):
                host_id = '{subnet_id}_host_{host}'.format(subnet_id=subnet_id,
                                                           host=host)

                rules += 'inSubnet({host_id}, {subnet_id}).\n'\
                            .format(subnet_id=subnet_id, host_id=host_id)

                if random() < vuln_prob:
                    if random() < local_app_prob:
                        app_type, exploit_type = 'local', 'local'
                        owner = 'root' if random() < root_prob else 'user'
                        rules += 'setuidProgramInfo({host_id}, localApplication, {owner}).\n'\
                                    .format(host_id=host_id, owner=owner)
                    else:
                        exploit_type = 'remote'
                        app_type = 'server' if random() < server_client_ratio else 'client'
                        priv = 'root' if random() < root_prob else 'user'
                        if app_type == 'server':
                            rules += 'networkServiceInfo({host_id}, serverApplication, httpProtocol, httpPort, {priv}).'\
                                .format(host_id=host_id, priv=priv)
                    for vuln in range(randint(1, max_vulns_host)):
                        vuln_id = '{host_id}_{exploit_type}Vul_{vuln}'\
                                    .format(host_id=host_id, exploit_type=exploit_type,
                                            vuln=vuln)
                        prob = random()
                        ac = 'h' if prob < high_prob else\
                             ('m' if prob - high_prob < medium_prob else 'l')
                        rules += '''
                                    vulExists({host_id}, {vuln_id}, {app_type}Application).
                                    vulProperty({vuln_id}, {exploit_type}Exploit, privEscalation).
                                    cvss({vuln_id}, {ac}).
                                 '''.format(host_id=host_id, vuln_id=vuln_id,
                                            app_type=app_type, exploit_type=exploit_type,
                                            ac=ac)

                if random() < victim_prob:
                    victim_id = '{host_id}_victim'.format(host_id=host_id)
                    priv = 'root' if random() < root_prob else 'user'
                    rules += '''inCompetent({victim_id}).
                                hasAccount({victim_id}, {host_id}, {priv}).
                             '''.format(victim_id=victim_id, host_id=host_id, priv=priv)

                if random() < internet_prob:
                    rules += 'hacl({host_id}, internet, httpProtocol, httpPort).\n'\
                                .format(host_id=host_id)
                if random() < internet_prob:
                    rules += 'hacl(internet, {host_id}, httpProtocol, httpPort).\n'\
                                .format(host_id=host_id)

        with open(output_path, 'w') as f:
            rules = [rule.strip() for rule in rules.splitlines()]
            f.write('\n'.join(rules))
        # print(rules)
    else:
        print('Usage: python3 generate.py <output_path> <num_hosts>')


if __name__ == '__main__':
    main()
