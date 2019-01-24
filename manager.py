# -*- coding: utf-8 -*-

from pathlib import Path

from colors import C
from policy import Policy

__author__ = 'Pawel Krawczyk'

try:
    from lxml import etree as etree
except ImportError:
    import xml.etree.ElementTree as etree

    print('Running with built-in XML parser, some input elements (e.g. comments) will be lost')


class RuleManager:
    class Collection:
        """
        This sub-class actually loads and parses a Wazuh XML rules file. Each such object represents
        one rules file. Internally it's a regular XML tree represented by etree.Element objects that
        also keeps meta-information such as XML comments (if lxml is used).
        """
        def __init__(self, collection_file: Path):
            # store rule file base name -`rules/rules.xml` becomes `rules.xml`
            self.filename = collection_file.name
            # Hack to work around Wazuh using pseudo-XML file syntax with many root tags
            # which crashes any regular XML parser. We wrap these roots inside an artificial
            # tag that works as single root for the whole document
            data = b'<rules>' + collection_file.read_bytes() + b'</rules>'
            # actually load and parse the XML rules file
            self.root = etree.fromstring(data)

        def get_all_rules(self):
            """
            Get all rules for this collection
            """
            # each collection (.xml file) can have several <group> which in turn have many <rule> elements
            # use XPath to iterate over rules
            return self.root.findall('./group/rule')

    def __init__(self, directory: Path):
        self.collections = []

        for collection_file in directory.glob('*.xml'):
            print('Processing', C.H, collection_file, C.X)
            self.collections.append(self.Collection(collection_file))

    def num_collections(self) -> int:
        return len(self.get_collections())

    def get_collections(self) -> list:
        return self.collections

    def num_rules(self) -> int:
        return len(list(self.get_all_rules()))

    def get_all_rules(self):
        for collection in self.collections:
            for rule in collection.get_all_rules():
                yield rule

    def apply_policy(self, policy: Policy):
        """
        Based on input from policy spreadsheet patch rules' levels.
        """
        for collection in self.collections:
            for rule_element in collection.get_all_rules():
                rule_id = rule_element.get('id')
                rule_policy = policy.get_rule_by_id(rule_id)
                if not rule_policy:
                    # this rule does not have policy entry
                    print(C.Y, 'WARNING:', C.X, 'rule', rule_id, 'does not have policy entry defined')
                    continue
                new_level = str(rule_policy.level)
                old_level = rule_element.get('level')
                print('Rule', C.H, rule_id, C.X, old_level, '⇢', new_level, end=' ')
                if new_level == old_level:
                    print('→', C.B, 'NO CHANGE', C.X)
                elif new_level > old_level:
                    print('↗', C.G, 'UPGRADE', C.X)
                    rule_element.set('level', new_level)
                else:
                    print('↘ ', C.Y, 'DOWNGRADE', C.X)
                    rule_element.set('level', new_level)

    def write(self, directory: Path):
        """
        Write modified Wazuh rules into XML files in the specific directory. Individual file
        names were previously stored on load in the Collection objects.
        """
        if not directory.is_dir():
            raise ValueError('The place to write rules must be a writable directory:', directory)

        for collection in self.collections:
            p = directory / Path(collection.filename)
            with p.open('wb') as out_file:
                print('Writing', p)
                for elem in collection.root.getchildren():
                    out_file.write(etree.tostring(elem))
