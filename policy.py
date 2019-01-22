# -*- coding: utf-8 -*-

import re
from collections import OrderedDict
import openpyxl

from colors import C

__author__ = 'Pawel Krawczyk'


class Policy:
    """
    Class that represents an abstract Wazuh policy incorporating all the rules. Rules are organized in Collections
    and reflect the customary organization of Wazuh rules into separate XML files.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.rules = OrderedDict()
        self._load()
        self.fixup()

    class Collection:
        """
        Rule collection reflecting one rules file such as `0016-wazuh_rules.xml`. Out of that we derive
        name (`wazuh`) and priority (`16`) which are later used in writing the rules back to disk.
        """

        def __init__(self, filename: str):
            self.filename = filename

            # generate collection name out of the filename
            if re.match(r'^\d+-[\w-]+\.xml$', filename):
                self.name = filename.split('-')[1].replace('.xml', '').replace('_rules', '')
                self.priority = int(filename.split('-')[0])
            elif re.match(r'^[\w-]+\.xml$', filename):
                self.name = filename.replace('.xml', '').replace('_rules', '')
            else:
                raise ValueError('Collection name does not follow the 0000-name_rules.xml convention', filename)

        def __str__(self):
            return self.filename

    class Rule:
        """
        A single Wazuh rule object.
        """

        def __init__(self, kv: dict):
            core_fields = {'id', 'collection'}
            if not core_fields.issubset(kv.keys()):
                raise ValueError('ERROR: rule without mandatory fields', core_fields, ', rule=', kv)

            for k, v in kv.items():
                if k is None:
                    print(C.Y, 'WARNING:', C.X, 'Ignoring cell in collection', kv['collection'].filename,
                          'without a heading value=', v)
                    print(kv)
                    continue
                self.__dict__[k] = v

        def __str__(self):
            return str(self.__dict__)

    def get_collections(self):
        ret = set()
        for rule in self.rules.values():
            ret.add(rule.collection)
        return ret

    def fixup(self) -> None:
        priorities = []
        for collection in self.get_collections():
            if hasattr(collection, 'priority'):
                priorities.append(collection.priority)
        last_priority = max(priorities)
        for collection in self.get_collections():
            if not hasattr(collection, 'priority'):
                last_priority += 100
                collection.priority = last_priority
                print(C.Y, 'WARNING:', C.X, 'Collection', collection, 'had no priority, assigning first available',
                      last_priority)

    def num_collections(self) -> int:
        return len(self.get_collections())

    def num_rules(self) -> int:
        return len(self.rules)

    def get_rule_by_id(self, rule_id: int) -> Rule:
        try:
            return self.rules.get(int(rule_id))
        except (KeyError, ValueError):
            try:
                return self.rules[rule_id]
            except KeyError:
                return self.rules.get(str(rule_id))

    def _load(self) -> None:

        policy_workbook = openpyxl.load_workbook(self.filename, read_only=True)

        for collection_filename in policy_workbook.sheetnames:

            if not collection_filename.endswith('.xml'):
                print(C.Y, 'WARNING:', C.X, 'Skipping collection', collection_filename,
                      'because its name doesn\'t end with .xml')
                continue

            rule_worksheet = policy_workbook[collection_filename]

            collection = self.Collection(collection_filename)

            # names of header fields for this collection used to map fields into rule
            rule_collection_headers = []
            in_heading_row = True  # type: bool

            for row in rule_worksheet.rows:

                rule_contents = {}

                col_idx = 0

                for cell in row:

                    if in_heading_row:
                        rule_collection_headers.append(cell.value)
                        continue

                    if cell.value is not None:
                        field_name = rule_collection_headers[col_idx]
                        rule_contents[field_name] = cell.value

                    col_idx += 1

                if in_heading_row:
                    in_heading_row = False
                    continue

                # reading cells completed, produce Rule object
                if not {'id', 'level'}.issubset(rule_contents.keys()):
                    print(C.Y, 'WARNING:', C.X, 'collection', collection.filename, ' has row without id and level',
                          rule_contents)
                    print(row)
                    continue

                # append collection information
                rule_contents["collection"] = collection

                new_rule = self.Rule(rule_contents)
                if new_rule.id in self.rules:
                    raise IndexError('Duplicate rule id={}, new rule={}\n old rule={}'.format(new_rule.id, new_rule,
                                                                                              self.rules[new_rule.id]))
                self.rules[new_rule.id] = new_rule
