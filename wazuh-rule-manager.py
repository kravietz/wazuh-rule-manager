#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
import json
import pathlib

from colors import C
from manager import RuleManager
from policy import Policy, PolicyEncoder

__author__ = 'Pawel Krawczyk'


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', help='Policy spreadsheet document file path', type=pathlib.Path)
    parser.add_argument('--new_policy', help='Produce a new policy spreadsheet from the rules', type=pathlib.Path)
    parser.add_argument('--rules', help='Path to the directory containing Wazuh XML rules', type=pathlib.Path)
    parser.add_argument('--fix', help='Fix missing fields (e.g. priority)', default=False, action='store_true')
    parser.add_argument('--out', help='Output directory or filename', type=pathlib.Path)
    parser.add_argument('--diff', help='Show diff between old and adjusted rules', default=False, action='store_true')
    parser.add_argument('--json', help='Output policy in JSON format', default=False, action='store_true')

    args = parser.parse_args()
    policy = rules = None

    if args.rules:
        rules = RuleManager(args.rules)
        print('Loaded', len(list(rules.get_all_rules())), 'rules from', len(rules.get_collections()), 'collections')

    if args.policy and args.new_policy:
        print('ERROR: --policy and --new-policy are mutually exclusive')
        exit(1)

    if args.new_policy:
        policy = Policy()
        policy.from_rules(rules)

        if args.fix:
            policy.fixup()

        print('Writing', C.H, args.new_policy, C.X)
        policy.write(args.new_policy)
        exit(0)

    if args.policy:
        policy = Policy()
        policy.from_file(args.policy)

        if args.fix:
            policy.fixup()

        print('Policy read: collections=', policy.num_collections(), ' rules=', policy.num_rules())

        if args.json:
            print(json.dumps(policy, indent=4, sort_keys=True, cls=PolicyEncoder))

    if args.rules and args.policy:
        print('Applying policy to rules')
        rules.apply_policy(policy)

        if args.out:
            rules.write(args.out)
