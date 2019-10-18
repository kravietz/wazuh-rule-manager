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

        # this structure is used to automatically map levels for rules that
        # do not have this mapping explicitly declared in policy
        # for example, always map level 12 -> 8
        self.level_map = {}

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

    def apply_policy(self, policy: Policy, old_max_level: int = 15, new_max_level: int = 10, overwrite: bool = False):
        """
        Based on input from policy spreadsheet, patch rules' levels.
        """
        for collection in self.collections:
            for rule_element in collection.get_all_rules():
                rule_id = rule_element.get('id')

                # XML returns str but we need level to be int
                old_level = int(rule_element.get('level'))

                # find a policy entry for this rule id
                rule_policy = policy.get_rule_by_id(rule_id)

                # determine new level to apply
                if rule_policy:
                    # either from rule policy entry for this id
                    # levels in policy are ints
                    new_level = int(rule_policy.level)
                else:
                    # or, no policy exists, then by mapping the default set
                    new_level = round((old_level - 1) / (old_max_level - 1) * (new_max_level - 1) + 1)
                    print(C.Y, 'WARNING:', C.X, 'rule', rule_id,
                          'does not have policy entry, applying computed mapping', new_level)

                # this is where we actually patch the rule
                # need to convert level back to str
                rule_element.set('level', str(new_level))

                if overwrite:
                    rule_element.set('overwrite', 'yes')

                # now levels from both sources are ints, which we need for comparison
                print('Rule', C.H, rule_id, C.X, old_level, '⇢', new_level, end=' ')
                if new_level == old_level:
                    print('→', C.B, 'NO CHANGE', C.X)
                elif new_level > old_level:
                    print('↗', C.G, 'UPGRADE', C.X)
                else:
                    print('↘ ', C.Y, 'DOWNGRADE', C.X)

    def _write_file(self, file: Path):
        with file.open('wb') as out_file:
            print('Writing rules to file', file)
            for collection in self.collections:
                print('Writing collection', collection.filename)
                for elem in collection.root.getchildren():
                    out_file.write(etree.tostring(elem).replace(b'&gt;', b'>'))

    def _write_dir(self, directory: Path):
        if not directory.is_dir():
            raise ValueError('The place to write rules must be a writable directory:', directory)

        for collection in self.collections:
            p = directory / Path(collection.filename)
            with p.open('wb') as out_file:
                print('Writing file', p)
                for elem in collection.root.getchildren():
                    out_file.write(etree.tostring(elem).replace(b'&gt;', b'>'))

    def write(self, output_where: Path, single_file: bool = False):
        """
        Write modified Wazuh rules into XML files in the specific directory. Individual file
        names were previously stored on load in the Collection objects.
        """
        if single_file:
            self._write_file(output_where)
        else:
            self._write_dir(output_where)
