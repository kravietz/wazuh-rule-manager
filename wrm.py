#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
import json
import pathlib

from manager import RuleManager
from policy import Policy

__author__ = 'Pawel Krawczyk'


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', help='Policy spreadsheet document file path', type=pathlib.Path)
    parser.add_argument('--rules', help='Path to the directory containing Wazuh XML rules', type=pathlib.Path)
    parser.add_argument('--fix', help='Fix missing fields (e.g. priority)', default=False, action='store_true')
    parser.add_argument('--out', help='Output directory or filename', type=pathlib.Path)
    parser.add_argument('--write', help='Write what', choices=['rules', 'policy'])
    parser.add_argument('--json', help='Output policy in JSON format', default=False, action='store_true')

    args = parser.parse_args()

    if args.rules:
        rule_manager = RuleManager(args.rules)

    if args.policy:
        policy = Policy(str(args.policy))

        if args.fix:
            policy.fixup()

        print('Policy read: collections=', policy.num_collections(), ' rules=', policy.num_rules())

        if args.json:
            class PolicyEncoder(json.JSONEncoder):
                def default(self, obj):
                    return obj.__dict__
            print(json.dumps(policy, indent=4, sort_keys=True, cls=PolicyEncoder))

    if args.rules and args.policy:
        print('Applying policy to rules')
        rule_manager.apply_policy(policy)

        if args.out:
            rule_manager.write(args.out)


