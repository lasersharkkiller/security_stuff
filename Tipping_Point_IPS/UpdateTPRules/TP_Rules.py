#can't remember the original source for this one
from __future__ import print_function

import csv
import hashlib
import os
import tarfile
from xml.etree import ElementTree as ET

config = {
    'check_value': 'name',
    'actionSets': {
        'permit_notify': '7d13fcaa-88bd-11d6-859b-0002b34b9580',
        'block_notify': '3ab8eea0-4331-11d6-b47a-00a0c995f27f',
        'disabled': '5f0db480-c647-441a-bdfd-48476fb1dce9',
        'trust_traffic_mgmt': '2dfa094a-b9a2-4305-9e81-93b357337f02'
    },
    'signatures': {
        'traffic_mgmt': '00000001-0001-0001-0001-000000001145'
    }
}


def load_CSV(file_path, _profile):
    _object = {}
    with open(file_path, 'rb') as _csv_file:
        reader = csv.DictReader(_csv_file)
        for row in reader:
            if row['profile'] == _profile:
                _object[row['name']] = {
                    'rule_id': row['id'],
                    'profile': row['profile']
                }
    print("[*] Imported {0} rules to edit for profile '{1}'.".format(len(_object), _profile))
    return _object


def load_XML(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    print("[*] Loaded XML file: {0}".format(file_path))
    print("[*] Rule file contains {0} entries".format(len(root.findall("./policy"))))
    return tree, root


def unpack_tar(file_path, unpack_path):
    tar = tarfile.open(file_path)
    tar.extractall(unpack_path)
    tar.close()


def pack_tar(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))


def replaceFileHash(initial_hash, new_hash, security_file):
    with open(security_file, "a+") as _file:
        for line in _file:
            line.write(line.replace(initial_hash, new_hash))


def getMD5Hash(file_path):
    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def disable_rule(_root, _node):
    _root.remove(_node)


def is_traffic_mgmt_rule(_node):
    _rule_id = _node.find('./signature').attrib['refid']
    if _rule_id != config['signatures']['traffic_mgmt']:
        return False
    return True


file = r'C:\Users\bam7c\Desktop\SecureCore\policies.xml'
tar_file = r'C:\Users\bam7c\Desktop\SecureCore.pkg'
profile = 'SecureCore'

#unpack_tar(tar_file,  r'C:\Users\bam7c\Desktop\SecureCore2')

tree, root = load_XML(file)
_csv = load_CSV(r'C:\Users\bam7c\Documents\Scripts\Python\ClassStore\File\RemovedFilters.csv', profile)
for rule, values in _csv.iteritems():
    # print(values['profile'])
    for node in root:
        try:
            if is_traffic_mgmt_rule(node):
                continue  # Pass if rule is for Traffic Management
            # node.find('./base/actionset').attrib['refid'] = config['actionSets']['permit_notify']
            if rule == node.attrib['name']:
                # print('done removed ' + node.attrib['name'])
                # disable_rule(root, node)
                continue
        except:
            continue

export_file = 'policies' + ".xml"
tree.write(export_file)
