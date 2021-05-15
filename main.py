#!./venv/bin/python

import re
import os
import requests
import getopt
import yaml
import sys
import tempfile
import git
import xml.etree.ElementTree as element_tree
from bs4 import BeautifulSoup


USAGE = """
usage main.py [-h] [-l LOG_PATH] [-q] [-s TYPES_TO_SKIP] [-i TYPE_CODE] CONFIG_PATH
    -h                  : show usage
    -l LOG_PATH         : define path to log file
    -q                  : run in quiet mode
    -s TYPES_TO_SKIP    : comma-separated issues types to skip
    -i TYPE_CODE        : det type info 
"""

HIDDEN_DETAILS = [
    "T2", "A1", "J1"
]

ISSUE_TYPES = {
    "A2": {
        "description": "Ansible code should not contain planetext secrets",
        "recommendations": "Use ansible-vault to encrypt all file or embed encrypted variable"
    },
    "A1": {
        "description": "Ansible code should not contain comments with bugs or vulnerabilities description",
        "recommendations": "Delete this comments"
    },
    "A3": {
        "description": "Configuring programms shoud not use 0.0.0.0 as configured address",
        "recommendations": "Use target ip instead 0.0.0.0"
    },
    "A4": {
        "description": "Ansible code shoud not contain http requests",
        "recommendations": "Configure https connection"
    },
    "A5": {
        "description": "Ansible should not execute all code as root or admin user",
        "recommendations": "Use become_user: root if it neccessary to escalate prevelegies"
    },
    "A6": {
        "description": "Ansible code should not contain sha1 and md5 hashes",
        "recommendations": "Use another hash algorythm, for example sha256"
    },
    "T1": {
        "description": "Terraform configurations should not contain contain comments with bugs or vulnerabilities description",
        "recommendations": "Delete this comments"
    },
    "T2": {
        "description": "Terraform configurations should not contain planetext secrets",
        "recommendations": "Mask sensetive data as variables and pass it as command line arguments"
    },
    "J2": {
        "description": "Jenkins code should not contain planetext secrets",
        "recommendations": "Use Jenkins credentials to manage secrets"
    },
    "J1": {
        "description": "Jenkins code should not contain comments with bugs or vulnerabilities description",
        "recommendations": "Delete this comments"
    },
    "J3": {
        "description": "Access by different user to different areas should be managed",
        "recommendations": "Use project-based or matrix access configurations."
    },
    "J4": {
        "description": "Jenkins server should be protected from common vulnerabilities",
        "recommendations": "Use organization or technickal solutions for all actual common vulnerabilities"
    },
}

log_path = "./check.log"
verbose = True


def log(message):
    if verbose:
        print(message)

    with open(log_path, "a") as log_file:
        log_file.write(message + "\n")


class CheckCore:
    """ Class to inherit with basic methods """

    def get_repo(self):
        """ Download git repo """
        log("[PROGRESS] Cloning repository")
        tmp_dir = tempfile.mkdtemp()
        src_url = "https://%s:%s@%s" % (self.repo_user, self.repo_password, self.repo_url.replace("https://", ""))
        try:
            git.Repo.clone_from(src_url, tmp_dir)
        except git.exc.GitCommandError as git_error:
            print("[ERROR] Error during cloning inventory: \n%s" % str(git_error).replace(self.repo_password, "****"))
            sys.exit(2)
        return tmp_dir

    def get_files_to_check(self, repo_path):
        """ Get list of files to check """
        files_to_check = []
        for path, subdirs, files in os.walk(repo_path):
            for name in files:
                for pattern in self.template_pattern:
                    if re.search(pattern, name):
                        files_to_check.append(os.path.join(path, name))
                        break
        return files_to_check


class Terraform(CheckCore):
    """ This class implements Terraform checks according methodology """
    template_pattern = [".*[.]tf", ".*[.]tf[.]j2"]
    broken = False

    def __init__(self, configurations):
        """ Initialization of Terraform configurations """
        log("[PROGRESS] Initializing Terraform checker")
        try:
            self.repo_url = configurations['repo_url']
            self.repo_user = configurations['repo_user']
            self.repo_password = configurations['repo_password']
            self.template_pattern = configurations['template_pattern']
        except KeyError as key:
            if not key == "'template_pattern'":
                log("[ERROR] Property %s doesn't set in configuration" % key)
                sys.exit(2)

    @staticmethod
    def check_file_for_suspicious_comment(file_to_check):
        """ Check file for suspicious comment """
        suspicious_keywords = [
            "bug", "fixme", "todo", "hack"
        ]
        comment_markers = [
            "#", "//", "/*", "*/"
        ]
        lines_with_comment = []
        force_scan = False

        log("[PROGRESS] Checking %s for suspicious comment" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for marker in comment_markers:
                if marker in line:
                    for keyword in suspicious_keywords or force_scan:
                        if re.search(keyword, line.split(marker)[1 if not marker == "*/" else 0], re.IGNORECASE):
                            lines_with_comment.append(line)
                            break
                    if marker == "/*":
                        force_scan = True
                    if marker == "*/":
                        force_scan = False
        return lines_with_comment

    @staticmethod
    def check_file_for_planetext_secrets(file_to_check):
        """ Check file for planetext secrets"""
        secret_keywords = [
            "token", "password", "ssh_key", "pass"
        ]
        lines_with_secret = []

        log("[PROGRESS] Checking %s for planetext secrets" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for keyword in secret_keywords:
                pattern = ".*%s.*[ ]=.*[ ]\".*\"" % keyword
                if re.search(pattern, line, re.IGNORECASE):
                    lines_with_secret.append(line)
                    break

        return lines_with_secret

    def check_configurations(self):
        """ Start point for methodology checks """
        log("[PROGRESS] Terraform checks started")
        repo_path = self.get_repo()
        files_to_check = self.get_files_to_check(repo_path)
        lines_with_errors = []
        for file_to_check in files_to_check:
            lines_with_comment = self.check_file_for_suspicious_comment(file_to_check)
            if lines_with_comment:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_comment,
                    "type": "T1"
                })
            lines_with_secret = self.check_file_for_planetext_secrets(file_to_check)
            if lines_with_secret:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_secret,
                    "type": "T2"
                })
        return lines_with_errors


class Ansible(CheckCore):
    """ This class implements Ansible checks according methodology """
    template_pattern = [".*[.]yml", ".*[.]yaml"]

    def __init__(self, configurations):
        """ Initialization of Ansible configurations """
        log("[PROGRESS] Initializing Ansible checker")
        try:
            self.repo_url = configurations['repo_url']
            self.repo_user = configurations['repo_user']
            self.repo_password = configurations['repo_password']
            self.template_pattern = configurations['template_pattern']
        except KeyError as key:
            if not str(key) == "'template_pattern'":
                print("[ERROR] Property %s doesn't set in configuration" % key)
                sys.exit(2)

    @staticmethod
    def check_file_for_suspicious_comment(file_to_check):
        """ Check file for suspicious comment """
        suspicious_keywords = [
            "bug", "fixme", "todo", "hack"
        ]
        comment_markers = [
            "#",
        ]
        lines_with_comment = []

        log("[PROGRESS] Checking %s for suspicious comment" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for marker in comment_markers:
                if marker in line:
                    for keyword in suspicious_keywords:
                        if re.search(keyword, line.split(marker)[1], re.IGNORECASE):
                            lines_with_comment.append(line)
                            break
        return lines_with_comment

    @staticmethod
    def check_file_for_planetext_secrets(file_to_check):
        """ Check file for planetext secrets"""
        secret_keywords = [
            "token", "password", "ssh_key"
        ]
        lines_with_secret = []

        log("[PROGRESS] Checking %s for planetext secrets" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for keyword in secret_keywords:
                pattern = ".*%s.*:[ ]*.*" % keyword
                vault_pattern = ".*%s.*:[ ]*(!vault).*" % keyword
                variable_pattern = ".*%s.*:[ ]*(\"[ ]*{{).*(}}[ ]*\")" % keyword
                if re.search(pattern, line, re.IGNORECASE) and not re.search(vault_pattern, line, re.IGNORECASE) and not re.search(variable_pattern, line, re.IGNORECASE):
                    lines_with_secret.append(line)
                    break

        return lines_with_secret

    @staticmethod
    def check_file_for_non_routing_addresses(file_to_check):
        """ Check file for 0.0.0.0 usage """

        lines_with_non_routing = []

        log("[PROGRESS] Checking %s for non-routing address" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            if "0.0.0.0" in line:
                lines_with_non_routing.append(line)

        return lines_with_non_routing

    @staticmethod
    def check_file_for_http_usage(file_to_check):
        """ Check file for unsecure http usage usage """

        lines_with_http = []

        log("[PROGRESS] Checking %s for http usage" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            if "http://" in line:
                lines_with_http.append(line)

        return lines_with_http

    @staticmethod
    def check_file_for_admin_users(file_to_check):
        """ Check file for unsecure http usage usage """

        lines_with_admin = []

        log("[PROGRESS] Checking %s for using admin users" % file_to_check)

        admin_patterns = [
            "admin", "root"
        ]

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for pattern in admin_patterns:
                if re.search(".*_user:.*[ ]%s" % pattern, line):
                    lines_with_admin.append(line)

        return lines_with_admin

    @staticmethod
    def check_file_for_unreliable_hashes(file_to_check):
        """ Check file for unsecure http usage usage """

        lines_with_hashes = []

        log("[PROGRESS] Checking %s for unreliable secrets" % file_to_check)

        hash_patterns = [
            "md5", "sha1"
        ]

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for pattern in hash_patterns:
                if pattern in line:
                    lines_with_hashes.append(line)

        return lines_with_hashes

    def check_configurations(self):
        """ Start point for methodology checks """
        log("[PROGRESS] Ansible checks started")
        repo_path = self.get_repo()
        files_to_check = self.get_files_to_check(repo_path)
        lines_with_errors = []
        for file_to_check in files_to_check:
            lines_with_comment = self.check_file_for_suspicious_comment(file_to_check)
            if lines_with_comment:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_comment,
                    "type": "A1"
                })
            lines_with_secret = self.check_file_for_planetext_secrets(file_to_check)
            if lines_with_secret:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_secret,
                    "type": "A2"
                })
            lines_with_non_routing = self.check_file_for_non_routing_addresses(file_to_check)
            if lines_with_non_routing:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_non_routing,
                    "type": "A3"
                })
            lines_with_http = self.check_file_for_http_usage(file_to_check)
            if lines_with_http:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_http,
                    "type": "A4"
                })
            lines_with_admin = self.check_file_for_admin_users(file_to_check)
            if lines_with_admin:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_admin,
                    "type": "A5"
                })
            lines_with_hashes = self.check_file_for_unreliable_hashes(file_to_check)
            if lines_with_admin:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_hashes,
                    "type": "A6"
                })

        return lines_with_errors


class Jenkins(CheckCore):
    """ This class implements Jenkins checks according methodology """
    template_pattern = [".*[.]Jenkinsfile", ".*[.]groovy"]
    broken = False

    def __init__(self, configurations):
        """ Initialization of Jenkins configurations """
        try:
            self.repo_url = configurations['repo_url']
            self.repo_user = configurations['repo_user']
            self.repo_password = configurations['repo_password']
            self.jenkins_url = configurations['jenkins_url']
            self.jenkins_user = configurations['jenkins_user']
            self.jenkins_password = configurations['jenkins_password']
            self.template_pattern = configurations['template_pattern']
        except KeyError as key:
            if not str(key) == "'template_pattern'":
                print("[ERROR] Property %s doesn't set in configuration" % key)
                sys.exit(2)

    @staticmethod
    def check_file_for_suspicious_comment(file_to_check):
        """ Check file for suspicious comment """
        suspicious_keywords = [
            "bug", "fixme", "todo", "hack"
        ]
        comment_markers = [
            "//", "/*", "*/"
        ]
        lines_with_comment = []
        force_scan = False

        log("[PROGRESS] Checking %s for suspicious comment" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for marker in comment_markers:
                if marker in line:
                    for keyword in suspicious_keywords or force_scan:
                        if re.search(keyword, line.split(marker)[1 if not marker == "*/" else 0], re.IGNORECASE):
                            lines_with_comment.append(line)
                            break
                    if marker == "/*":
                        force_scan = True
                    if marker == "*/":
                        force_scan = False
        return lines_with_comment

    @staticmethod
    def check_file_for_planetext_secrets(file_to_check):
        """ Check file for planetext secrets"""
        secret_keywords = [
            "token", "password", "ssh_key", "pass"
        ]
        lines_with_secret = []

        log("[PROGRESS] Checking %s for planetext secrets" % file_to_check)

        with open(file_to_check, 'r') as f:
            file_lines = f.readlines()

        for line in file_lines:
            for keyword in secret_keywords:
                pattern = ".*%s.*[ ][=:].*[ ]\".*\"" % keyword
                if re.search(pattern, line, re.IGNORECASE):
                    lines_with_secret.append(line)
                    break

        return lines_with_secret

    def check_access_configurations(self):
        """ Check Jenkins access configurations """
        secure_mods = [1, 4]

        log("[PROGRESS] Checking %s for insecure access configurations" % self.jenkins_url)

        get_users = requests.get(
            "%s/asynchPeople/api/xml?depth=1" % self.jenkins_url,
            auth=(self.jenkins_user, self.jenkins_password),
            headers={"Content-Type": "application/xml"},
            verify=False)
        get_security = requests.get(
            "%s/configureSecurity" % self.jenkins_url,
            auth=(self.jenkins_user, self.jenkins_password),
            headers={"Content-Type": "application/xml"},
            verify=False)
        soup = BeautifulSoup(get_security.text, "lxml")

        input_text = soup.select("input[name='authorization'][checked='true']")
        value_search = re.search("value=\"(.*)\"", str(input_text))
        value = value_search.group(1)

        access_errors = []

        if value not in secure_mods:
            access_errors.append("Insecure authorization method used")

        tree = element_tree.fromstring(get_users.text)
        users = [el[0][0].text.split("/")[len(el[0][0].text.split("/")) - 1] for el in tree]
        if len(users) == 1:
            access_errors.append("Only one user for Jenkins manipulations created")

        return access_errors

    def check_vulnerabilities(self):
        """ Check Jenkins version for CVE """
        log("[PROGRESS] Checking %s for vulnerabilities" % self.jenkins_url)

        cve_patterns = [
            r"Jenkins before ([\d\.]+)",
            r"Jenkins main before ([\d\.]+)",
            r"Jenkins ([\d\.]+) and earlier",
            r"Jenkins versions ([\d\.]+) and earlier",
            r"Jenkins ([\d\.]+)",
            r"Jenkins ([\d\.]+) and older",
            r"jenkins before versions ([\d\.]+)"
        ]
        get_version = requests.get(
            "%s/configureSecurity" % self.jenkins_url,
            auth=(self.jenkins_user, self.jenkins_password),
            headers={"Content-Type": "application/xml"},
            verify=False)

        version = get_version.headers['X-Jenkins']

        get_cve = requests.get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=jenkins")

        soup = BeautifulSoup(get_cve.text, "lxml")
        tr_list = soup.select("div#TableWithRules>table>tr")
        vulnerabilities_list = []
        split_version = version.split(".")
        for tr in tr_list:
            for pattern in cve_patterns:
                cve_version = re.search(pattern, tr.contents[3].string, re.IGNORECASE)
                if cve_version:
                    cve_version_number = cve_version.group(1)
                    cve_split_version = cve_version_number.split(".")
                    cve_info = "%s: %s" % (tr.contents[1].string.strip(), tr.contents[3].string.strip())
                    if "." not in cve_version_number:
                        continue
                    if int(cve_split_version[0]) > int(split_version[0]):
                        vulnerabilities_list.append(cve_info)
                    elif int(cve_split_version[0]) == int(split_version[0]) and int(cve_split_version[1]) > int(split_version[1]):
                        vulnerabilities_list.append(cve_info)
                    elif int(cve_split_version[0]) == int(split_version[0]) and int(cve_split_version[1]) == int(split_version[1]) and int(cve_split_version[3]) >= int(split_version[3]):
                        vulnerabilities_list.append(cve_info)
                    break
        return vulnerabilities_list

    def check_configurations(self):
        """ Start point for methodology checks """
        log("[PROGRESS] Jenkins checks started")

        self.check_vulnerabilities()

        repo_path = self.get_repo()
        files_to_check = self.get_files_to_check(repo_path)
        lines_with_errors = []

        access_check = self.check_access_configurations()
        if access_check:
            lines_with_errors.append({
                "file": self.jenkins_url,
                "strings": access_check,
                "type": "J3"
            })

        vulnerabilities_check = self.check_vulnerabilities()
        if vulnerabilities_check:
            lines_with_errors.append({
                "file": self.jenkins_url,
                "strings": vulnerabilities_check,
                "type": "J4"
            })

        for file_to_check in files_to_check:
            lines_with_comment = self.check_file_for_suspicious_comment(file_to_check)
            if lines_with_comment:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_comment,
                    "type": "J1"
                })
            lines_with_secret = self.check_file_for_planetext_secrets(file_to_check)
            if lines_with_secret:
                lines_with_errors.append({
                    "file": file_to_check.replace(repo_path, ""),
                    "strings": lines_with_secret,
                    "type": "J2"
                })

        return lines_with_errors


if __name__ == '__main__':
    log_path = "./check.log"
    skip_types = []

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:qi:s:")
    except getopt.GetoptError as error:
        print(error)
        print(USAGE)
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print(USAGE)
            sys.exit(0)
        if opt == "-l":
            log_path = arg
        if opt == "-q":
            verbose = False
        if opt == "-i":
            try:
                print("---- " + arg + " ----")
                print("Description: %s\nRecommendations: %s" % (ISSUE_TYPES[arg]['description'], ISSUE_TYPES[arg]['recommendations']))
                sys.exit(0)
            except KeyError as no_key:
                print("[ERROR] No such issue type")
                sys.exit(0)
        if opt == "-s":
            skip_types = arg.split(",")

    if len(args) > 1:
        print("[WARNING] More than one configuration file provided, others will be ignored!")
    if len(args) == 0:
        print("[ERROR] No configuration file provided!")
        sys.exit(2)

    configuration_file = args[0]

    try:
        with open(configuration_file) as file:
            configuration_list = yaml.load(file, Loader=yaml.FullLoader)
    except IOError as error:
        print(error)
        sys.exit(2)

    try:
        file = open(log_path, "w")
    except IOError as error:
        print(error)
        sys.exit(2)

    terraform_configurations = []
    ansible_configurations = []
    jenkins_configurations = []

    for configuration_name, configuration_content in configuration_list.items():
        if configuration_name == "terraform":
            terraform_configurations.append(configuration_content)
        if configuration_name == "ansible":
            ansible_configurations.append(configuration_content)
        if configuration_name == "jenkins":
            jenkins_configurations.append(configuration_content)

    results = []
    for configuration in terraform_configurations:
        terraform = Terraform(configuration)
        result = terraform.check_configurations()
        results.append(result)

    for configuration in ansible_configurations:
        ansible = Ansible(configuration)
        result = ansible.check_configurations()
        results.append(result)

    for configuration in jenkins_configurations:
        jenkins = Jenkins(configuration)
        result = jenkins.check_configurations()
        results.append(result)

    log("[SUCCESS] Security checks finished!\nRESULTS:")
    for phase in results:
        for result in phase:
            if result['type'] not in skip_types:
                log("+--------------------------------------------------------------+")
                log("%s Issue in %s:" % (result['type'], result['file']))
                log(ISSUE_TYPES[result['type']]['description'])
                log("Details:")
                if result['type'] not in HIDDEN_DETAILS:
                    counter = 0
                    for string in result['strings']:
                        counter += 1
                        log("%s. %s" % (counter, string.strip()))
                else:
                    log("Details was hidden")
                log("Recommendations: %s" % ISSUE_TYPES[result['type']]['recommendations'])
