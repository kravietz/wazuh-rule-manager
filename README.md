# wazuh-rule-manager

Command line tool to review, merge and modify OSSEC/Wazuh rules in bulk. This tool is now in **alpha** stage so be
careful. Typical workflow:

1. Parse XML rules and produce a spreadsheet (XLSX) **✋ not implemented**
2. Present the spreadsheet to your leadership, auditors, infosec working group for review and tuning
3. Working group adjusts some `level` fields in the spreadsheet, which now becomes your *policy file*
4. The tool reads policy file and XML rules, and outputs new XML rules with levels adjusted accordingly

Other features:

* Upgrade and merge rules from GitHub **✋ not implemented**
* Audit XML rules against the policy  **✋ not implemented**
* Fix some missing fields and inconsistencies
* Dump the policy into JSON
* Dump the policy into YAML **✋ not implemented**

## Usage

Assuming input rules are in `rules` directory and output rules are to be written into `out_rules`:

    python3 wazuh-rule-manager.py --rules rules
    
    python3 wazuh-rule-manager.py --rules rules --policy policy.xlsx
    
    python3 wazuh-rule-manager.py --rules rules --policy policy.xlsx --out out_rules
