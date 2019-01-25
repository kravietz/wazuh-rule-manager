# wazuh-rule-manager

Command line tool to review, merge and modify OSSEC/Wazuh rules in bulk. This tool is now in **alpha** stage so be
careful. Typical workflow:

1. Parse XML rules and produce a spreadsheet (XLSX) **✋ not implemented**
2. Present the spreadsheet to your leadership, auditors, infosec working group for review and tuning
3. Working group adjusts some `level` fields in the spreadsheet, which now becomes your *policy file*
4. The tool reads policy file and XML rules, and outputs new XML rules with levels adjusted accordingly

Other features:

* Upgrade and merge rules from GitHub
* Audit XML rules against the policy
* Fix some missing fields and inconsistencies
* Dump the policy into JSON
* Dump the policy into YAML **✋ not implemented yet**

## Usage

Assuming input rules are in `rules` directory and output rules are to be written into `out_rules` you may want to 
run the following commands:

* Analyze your existing rules and check for possible inconsistencies


    python3 wazuh-rule-manager.py --rules rules
    
* Generate new policy from existing rules, fixing inconsistencies


    python3 wazuh-rule-manager.py  --rules rules --new_policy new_policy.xlsx --fix
    
* Manually review the `new_policy.xlsx` file and adjust the `level` fields and save to `adjusted_policy.xlsx`.
  Then check what would get changed in actual XML rules in dry run mode:
 
    
    python3 wazuh-rule-manager.py --rules rules --policy adjusted_policy.xlsx
    
* Generate a new adjusted rule set and write it into `out_rules` directory, and display a diff between
    existing and adjusted rules afterwards: 
    
    
    python3 wazuh-rule-manager.py --rules rules --policy adjusted_policy.xlsx --out out_rules --diff
