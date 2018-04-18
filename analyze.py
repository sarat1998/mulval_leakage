import sys
from collections import OrderedDict
import tempfile
import shutil
import subprocess
import os
import re
from tabulate import tabulate


script_path = '/home/sarat/Programs/mulval/utils/riskAssess.sh'
leakage_path = '/home/sarat/Programs/mulval/kb/leakage_rules.P'


def get_risks(vertices_path):
    pattern = r'\d+,\"execCode\((\w+),\w+?\)\",\"OR\",([.\d]+)'
    with open(vertices_path, 'r+') as f:
        risks = dict(re.findall(pattern, f.read()))
        f.seek(0)
        f.truncate()
    return risks


def main():
    if len(sys.argv) == 2:
        test_path = os.path.abspath(sys.argv[1])
        try:
            dir_path = tempfile.mkdtemp()
            shutil.copy2(test_path, dir_path)
            test_path = os.path.join(dir_path, os.path.basename(test_path))
            script_cmd = [script_path, test_path, '--cvss', '-a', leakage_path]

            with open(os.devnull, 'w') as null:
                exit_code = subprocess.call(script_cmd, cwd=dir_path, stdout=null,
                                            stderr=null)
                if exit_code != 0:
                    raise Exception('No attack graph generated')
            vertices_path = os.path.join(dir_path, 'VERTICES.CSV')
            risks = get_risks(vertices_path)
            hosts = list(risks.keys())
            headers = ['Host', 'Initial']
            print(tabulate([[host, risks[host]] for host in hosts],
                           tablefmt='grid', headers=headers) + '\n')

            with open(test_path, 'r') as f:
                test_txt = f.read()
            vul_exists = re.compile(r'vulExists\(.+?,\s*(\S+?)\s*(?:,.+?){1,4}\)\.')
            vul_fact = r'(?:vulExists|vulProperty|cvss)\(.*?{}.*?\)\.'
            vul_ids = re.findall(vul_exists, test_txt)
            with open(test_path, 'w') as f:
                for vul_id in vul_ids:
                    f.seek(0)
                    f.write(re.sub(vul_fact.format(vul_id), '', test_txt))
                    f.flush()

                    with open(os.devnull, 'w') as null:
                        subprocess.call(script_cmd, cwd=dir_path, stdout=null,
                                        stderr=null)
                    risks = get_risks(vertices_path)
                    headers[1] = 'Patch ' + vul_id
                    print(tabulate([[host, risks.get(host, 0)] for host in hosts],
                                   tablefmt='grid', headers=headers) + '\n')
        except Exception as e: print(e)
        finally:
            shutil.rmtree(dir_path)
    else:
        print('Usage: python3 prioritize.py <test_path>')


if __name__ == '__main__':
    main()
