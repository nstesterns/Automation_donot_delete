import copy
import json
import logging
import os
import re

os.environ["app_user"] = "default"
#from apps.desktop.web.gmail.gmailconfig import *

code_dir = './tests/desktop/web/workplacebyfacebook'
test_dir = ""

# below commented code is for verifying with TestRail for active tests
# test_plan = "Release 78 Connector Automation Regression-Altos-Enabled"
# PROJECT_NAME = "Netskope Engineering Test Project"

logger = logging.getLogger('test_migration_to_json')
logging.basicConfig(level=logging.DEBUG,
                    filename='migration.log',
                    filemode='w')

automation_tests_from_test_rail = []
test_jsons = {
    'all_block_tests': {},
    'all_alert_tests': {},
    'app_category_block_tests': {},
    'app_category_alert_tests': {},
    'app_instance_block_tests': {},
    'app_instance_alert_tests': {},
    'pci_block_tests': {},
    'pci_alert_tests': {},
    'phi_block_tests': {},
    'phi_alert_tests': {},
    'pii_block_tests': {},
    'pii_alert_tests': {},
    'profanity_block_tests': {},
    'profanity_alert_tests': {},
    'sourcecode_block_tests': {},
    'sourcecode_alert_tests': {},
    'file_size_block_tests': {},
    'file_size_alert_tests': {},
    'file_type_block_tests': {},
    'file_type_alert_tests': {},
    'dlp_file_size_block_tests': {},
    'dlp_file_size_alert_tests': {},
    'dlp_file_type_block_tests': {},
    'dlp_file_type_alert_tests': {},
    'non_dlp_user_alert_alert_tests': {},
    'non_dlp_user_alert_block_tests': {},
    'dlp_user_alert_alert_tests': {},
    'dlp_user_alert_block_tests': {}
}


def run_action(app_name, action_name, ns_app_name, trigger_name, object_type, **kwargs):
    if 'category' not in kwargs:
        kwargs['category'] = "Regression"
    if test_dir.endswith("all") or test_dir.endswith("block") or test_dir.endswith("all_new"):
        rule_type = "all"
    elif test_dir.endswith("app-category") or test_dir.endswith("App-Category-Based") \
            or test_dir.endswith("Appcategory") or test_dir.endswith("app_category"):
        rule_type = "app_category"
    elif test_dir.endswith("app-instance") or test_dir.endswith("app_instance") or test_dir.endswith("Instance-Based") \
            or test_dir.endswith("Appinstance") or test_dir.endswith("app-nstance"):
        rule_type = "app_instance"
    elif test_dir.endswith("dlp-file_size") or test_dir.endswith("dlp-filesize") or test_dir.endswith("dlpfliesize") \
            or test_dir.endswith("DLP-Filesize"):
        rule_type = "dlp_file_size"
    elif test_dir.endswith("dlp-file_types") or test_dir.endswith("dlp-file-types") or test_dir.endswith("dlp_filetypes") \
            or test_dir.endswith("DLP-filetype") or test_dir.endswith("pci-file_types") or test_dir.endswith("dlpfiletype") \
            or test_dir.endswith("dlp-filetype"):
        rule_type = "dlp_file_type"
    elif test_dir.endswith("dlp-pci") or test_dir.endswith("DLP-block"):
        rule_type = "pci"
    elif test_dir.endswith("dlp-phi"):
        rule_type = "phi"
    elif test_dir.endswith("dlp-pii"):
        rule_type = "pii"
    elif test_dir.endswith("dlp-profanity"):
        rule_type = "profanity"
    elif test_dir.endswith("dlp-sourcecode"):
        rule_type = "sourcecode"
    elif test_dir.endswith("file_size") or test_dir.endswith("Filesize"):
        rule_type = "file_size"
    elif test_dir.endswith("file_types") or test_dir.endswith("filetype") or test_dir.endswith("file_type"):
        rule_type = "file_type"
    elif test_dir.endswith("nondlp-user-alert") or test_dir.endswith("UA-Proceed") or test_dir.endswith("nondlpuseralert") or test_dir.endswith("non-dlp-user-alert"):
        rule_type = "non_dlp_user_alert"
    elif test_dir.endswith("dlp-user-alert") or test_dir.endswith("dlp-user-alert") or test_dir.endswith('DLP-UA') \
            or test_dir.endswith("DLPUA-proceed") or test_dir.endswith("dlpuseralert"):
        rule_type = "dlp_user_alert"
    elif test_dir.endswith("customer-issue") or test_dir.endswith("customer") \
            or test_dir.endswith("custom_block_template") or test_dir.endswith("custom_useralert_template") \
            or test_dir.endswith("login-testcases") or test_dir.endswith("fromuser") or test_dir.endswith("appfeaturesupport"):
        return

    test_case = {
        'app_name': app_name,
        "testrail_id": None,
        'object_type': object_type,
        "test_name": "{}_{}".format(app_name, action_name),
        'tags': kwargs['category'].split(","),
        'test_method': {
            'name': action_name,
        },
        "assert_result": False,
        "policy_enabled": True,
        'policy_data': {
            'app_name': ns_app_name,
            "app_or_category": 'app',
            "list_of_constraints": None,
            'activities': [{
                'activity': trigger_name
            }]
        }
    }
    test_identifiers = kwargs['test_id']

    del kwargs['test_id']
    del kwargs['category']
    test_case['test_method']['args'] = kwargs

    if rule_type == "app_category":
        test_case['policy_data']['app_or_category'] = "category"
        test_case['policy_data']["app_category"] = "Collaboration"
    elif rule_type == "app_instance":
        test_case['policy_data']['app_or_category'] = "app_instance"
    elif rule_type == "pci":
        test_case['policy_data']["dlp_profile"] = ["DLP-PCI"]
    elif rule_type == "phi":
        test_case['policy_data']["dlp_profile"] = ["DLP-PHI"]
    elif rule_type == "pii":
        test_case['policy_data']["dlp_profile"] = ["DLP-PII"]
    elif rule_type == "profanity":
        test_case['policy_data']["dlp_profile"] = ["DLP-Profanity"]
    elif rule_type == "sourcecode":
        test_case['policy_data']["dlp_profile"] = ["DLP-SourceCode"]
    elif rule_type == "file_size":
        test_case['policy_data']["file_size"] = {"operator": None, "size": None, "unit": None}
        file_name = list((test_case['test_method']['args']).values())[0]
        if "greater" in file_name.lower():
            test_case['policy_data']["file_size"]["operator"] = "gt"
        else:
            test_case['policy_data']["file_size"]["operator"] = "lt"

        if "mb" in file_name.lower():
            test_case['policy_data']["file_size"]["unit"] = "MB"
        else:
            test_case['policy_data']["file_size"]["unit"] = "KB"

        size = re.findall(r'\d+', file_name)[0]
        test_case['policy_data']["file_size"]["size"] = size
    elif rule_type == "file_type":
        test_case['policy_data']["file_types"] = [list((test_case['test_method']['args']).values())[0]]
    elif rule_type == "dlp_file_size":
        test_case['policy_data']["dlp_profile"] = ["DLP-PCI"]

        test_case['policy_data']["file_size"] = {"operator": None, "size": None, "unit": None}
        file_name = list((test_case['test_method']['args']).values())[0]
        if "greater" in file_name.lower():
            test_case['policy_data']["file_size"]["operator"] = "gt"
        else:
            test_case['policy_data']["file_size"]["operator"] = "lt"

        if "mb" in file_name.lower():
            test_case['policy_data']["file_size"]["unit"] = "MB"
        else:
            test_case['policy_data']["file_size"]["unit"] = "KB"

        size = re.findall(r'\d+', file_name)[0]
        test_case['policy_data']["file_size"]["size"] = size
    elif rule_type == "dlp_file_type":
        test_case['policy_data']["dlp_profile"] = ["DLP-PCI"]
        test_case['policy_data']["file_types"] = [list((test_case['test_method']['args']).values())[0]]
    elif rule_type == "dlp_user_alert":
        test_case['policy_data']["dlp_profile"] = ["DLP-PCI"]

    block_test = copy.deepcopy(test_case)
    alert_test = copy.deepcopy(test_case)

    if 'block-tid' in test_identifiers:
        block_test['testrail_id'] = test_identifiers['block-tid']
        if "alert-tid" in test_identifiers:
            alert_test['testrail_id'] = test_identifiers['alert-tid']
    elif "useralert-dlp-tid" in test_identifiers:
        block_test['testrail_id'] = test_identifiers['useralert-dlp-tid']
        alert_test['testrail_id'] = test_identifiers['useralert-dlp-tid']
    elif "useralert-tid" in test_identifiers:
        block_test['testrail_id'] = test_identifiers['useralert-tid']
        alert_test['testrail_id'] = test_identifiers['useralert-tid']
    else:
        block_test['testrail_id'] = test_identifiers['block-filetype-tid']
        if "alert-filetype-tid" in test_identifiers:
            alert_test['testrail_id'] = test_identifiers['alert-filetype-tid']
    alert_test['assert_result'] = True

    block_test['policy_data']['action'] = {"action_name": "block", "template": "block_page.html"}
    block_test['uj_options'] = 'OK'
    alert_test['policy_data']['action'] = {"action_name": "alert"}
    if rule_type in ['dlp_user_alert', 'non_dlp_user_alert']:
        block_test['policy_data']['action'] = {"action_name": "useralert",
                                               "template": "useralert_justify.html"}
        block_test['uj_options'] = 'stop'
        alert_test['policy_data']['action'] = {"action_name": "useralert",
                                               "template": "useralert_justify.html"}
        alert_test['uj_options'] = 'proceed'
    test_jsons[rule_type + "_block_tests"].setdefault('tests',[]).append(block_test)
    test_jsons[rule_type + "_alert_tests"].setdefault('tests',[]).append(alert_test)

# below commented code is for verifying with TestRail for active tests
# tl = TestRailAPI()
# test_run_id = tl.get_runid(test_plan, PROJECT_NAME)
#
# if not test_run_id:
#     logger.error("Unable to fetch Test RunID for %s  %s", PROJECT_NAME, test_plan)
# if test_run_id:
#     tests_info = tl.get_tests_by_status_run_id(test_run_id, "1,2,3,4,5")
#     automation_tests_from_test_rail = [str(test['case_id']) for test in tests_info]


sub_folders = [f.path for f in os.scandir(code_dir) if f.is_dir()]

for tmp_folder in sub_folders:
    test_dir = tmp_folder
    print ("test dir::: ", test_dir)
    for code_file in os.listdir(test_dir):
        code_line = ""
        if os.path.isdir(os.path.join(test_dir, code_file)):
            continue
        f = open(os.path.join(test_dir, code_file), "r")
        append = False
        for x in f:
            cur_line = x.strip()
            if cur_line.startswith("run_action"):
                append = True
            if append:
                code_line += cur_line
            if cur_line.endswith(")"):
                break
        logger.debug("%s contains function call: %s", code_file, code_line)
        exec(code_line)
    for key, val in test_jsons.items():
        with open(os.path.join(code_dir, key + ".json"), "w") as outfile:
            outfile.write(json.dumps(val, indent=4))
