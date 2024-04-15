# Copyright: (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import traceback
from os import urandom
import os.path
from platform import system
from base64 import b64encode, b64decode
from ansible import context, constants
from ansible.errors import AnsibleError, AnsibleModuleError
from ansible.executor.task_executor import TaskExecutor
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.yaml.objects import AnsibleMapping
from ansible.plugins.action import ActionBase

try:
    from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import NORMALIZE_NAMES, NORMALIZE_NAMES_SHORT
except ImportError:
    try:
        from ansible_collections.community.crypto.plugins.module_utils.crypto import NORMALIZE_NAMES, NORMALIZE_NAMES_SHORT
    except ImportError:
        NORMALIZE_NAMES_FOUND = False
    else:
        NORMALIZE_NAMES_FOUND = True
else:
    NORMALIZE_NAMES_FOUND = True


class CheckModeChanged(Exception):
    def __init__(self, message=""):
        super(CheckModeChanged, self).__init__(message)

        self.message = message

    def __str__(self):
        return self.message


class ActionModule(ActionBase):
    _task_vars = None
    _check_mode = False

    _changed = False
    _warnings = []

    _remote_temp = None
    _local_temp = None

    _ca_info = None

    _vars = {
        'select_crypto_backend': "auto",
        'enable_cert_creation': False,
        'force': False,

        'ca_host': "127.0.0.1",
        'ca_host_options': {},

        'private_key_path': None,
        'cert_path': None,
        'ca_cert_path': None,
        'fullchain_cert_path': None,

        'archive_dir_path': None,
        'archive_path': None,

        'ca_config_path': None,

        'private_key_length': 4096,
        'private_key_type': "RSA",
        'private_key_mode': 0o600,
        'private_key_curve': None,
        'cert_mode': 0o644,

        'ca': {
            'certificate': None,
            'private_key': None,
            'certificate_path': None,
            'private_key_path': None,
            'valid_at': '+720h'
        },

        'assert': {
            'signature_algorithm': [
                "sha256WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ],
            'subject': True,
            'issuer': True,
            'expired': True,
            'version': 3,
            'key_usage': True,
            'key_usage_critical': True,
            'extended_key_usage': True,
            'extended_key_usage_critical': True,
            'san': True,
            'san_critical': True,
            'valid_at': True,
            'ca_expired': True,
            'ca_valid_at': True,
            'remote_private_key': True,
        },

        'profile': '_default',
        'profiles': {
            '_default': {
                'expiry': "+43800h",
                'valid_at': '+720h',
                'key_usage': [],
                'key_usage_critical': False,
                'extended_key_usage': [],
                'extended_key_usage_critical': False,
                'san_critical': False
            },
        }
    }

    _X509_key_usage_name_map = {
        'Digital Signature': "digitalSignature",
        'Non Repudiation': "nonRepudiation",
        'Key Encipherment': "keyEncipherment",
        'Data Encipherment': "dataEncipherment",
        'Key Agreement': "keyAgreement",
        'Certificate Sign': "keyCertSign",
        'CRL Sign': "cRLSign",
        'Encipher Only': "encipherOnly",
        'Decipher Only': "decipherOnly",
    }

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        super(ActionModule, self).run(tmp, task_vars)
        del tmp

        self._strategy = getattr(constants, 'DEFAULT_STRATEGY')
        self._is_mitogen = self._strategy.startswith('mitogen')

        self._task_vars = task_vars
        self._check_mode = self._global_var("ansible_check_mode")

        # Disable check mode to enable necessary changes to check certificates
        self._task_vars['ansible_check_mode'] = False
        self._play_context.check_mode = False
        self._task.check_mode = False

        ActionModule._update(self._vars, self._task.args)

        self._var("private_key_path")
        self._var("cert_path")

        ret = {}

        try:
            self._precheck()
            self._main()
        except AnsibleModuleError as e:
            ret = e.orig_exc
        except CheckModeChanged as e:
            ret['msg'] = e.message
        finally:
            self._clean_up()

        ret['changed'] = self._changed

        if len(self._warnings):
            ret['warning'] = '\n'.join(self._warnings)

        return ret

    def _var(self, name):
        var = self._var_opt(name)

        if var is None:
            raise AnsibleError("Variable '{0}' not defined".format(name))

        return var

    def _global_var(self, name):
        if name not in self._task_vars:
            raise AnsibleError("Variable '{0}' not defined".format(name))

        return self._task_vars[name]

    def _var_opt(self, name):
        if name not in self._vars:
            return None

        return self._vars[name]

    def _ca_var(self, name):
        if name not in self._vars['ca']:
            return None

        return self._vars['ca'][name]

    def _profile_var(self, name, default=None):
        profile = self._var("profile")
        var = self._vars['profiles'][profile]

        if var is None:
            raise AnsibleError("Profile '{0}' not defined".format(profile))

        if var[name] is None:
            if default is not None:
                return default

            raise AnsibleError("Variable '{0}' not defined in profile '{1}'".format(name, profile))

        return var[name]

    def _check_result(self, module_name, run_on_ca_host, result=None, ignore_changed=False, ignore_failed=False):
        if not ignore_failed and 'failed' in result and result['failed']:
            if self._task_vars['ansible_verbosity'] > 2:
                result['action_stack'] = ''.join(traceback.format_stack())

            result['module_msg'] = "No message"
            if 'msg' in result:
                result['module_msg'] = result['msg']
            elif 'message' in result:
                result['module_msg'] = result['message']

            host_type = "target host"
            if run_on_ca_host:
                host_type = "ca host"

            result['msg'] = "Error during {0} module execution on {1}".format(module_name, host_type)

            if 'ansible_delegated_vars' in result:
                del result['ansible_delegated_vars']
            if '_ansible_delegated_vars' in result:
                del result['_ansible_delegated_vars']

            raise AnsibleModuleError(result['msg'], orig_exc=result)

        if not ignore_changed and 'changed' in result and result['changed']:
            self._changed = True

    def __execute_module(self, module_name=None, module_args=None, persist_files=False, delete_remote_tmp=None,
                         wrap_async=False, run_on_ca_host=False, ignore_changed=False, ignore_failed=False):
        if run_on_ca_host:
            host = InventoryManager(DataLoader(), context.CLIARGS['inventory']).get_host(self._var("ca_host"))

            task = self._task.copy()

            task_data = self._var("ca_host_options")
            task_data.update({
                'name': "mgssl ca_host task: {0}".format(module_name),
                'action': module_name,
                'args': module_args,
                'delegate_to': self._var("ca_host")
            })

            task.load_data(task_data)

            task_vars = self._task_vars.copy()
            task_vars.update(self._task.get_variable_manager().get_vars(host=host, task=task))

            try:
                executor_result = TaskExecutor(
                    host,
                    task,
                    task_vars,
                    self._play_context,
                    None,
                    self._loader,
                    self._shared_loader_obj,
                    None,
                    self._task.get_variable_manager()
                )
            except TypeError:
                try:
                    executor_result = TaskExecutor(
                        host,
                        task,
                        task_vars,
                        self._play_context,
                        None,
                        self._loader,
                        self._shared_loader_obj,
                        None
                    )
                except:
                    raise TypeError("TaskExecutor: Wrong type of object") from None

            # Dirty fix for mitogen compatibility
            # Mitogen somehow puts a task global connection binding object in each connection that gets created
            # during the lifetime of a task. That usually happens on the beginning of a task, but here, we create
            # a new task executor within a task and that also creates a new connection for local running tasks.
            # After execution the connections get closed, but the close function also closes and removes the parent
            # tasks binding object. Now all future connections will fail.
            #
            # Solution: Overwrite the close method and only call the necessary close methods except the one that closes
            # the binding object
            if self._is_mitogen:
                get_connection_method = executor_result._get_connection

                def get_connection(cvars, templar, current_connection):
                    c = get_connection_method(cvars, templar, current_connection)
                    c.close = lambda: (c._put_connection(), None)
                    return c

                executor_result._get_connection = get_connection

            ret = executor_result.run()

            # Reset the close method
            if self._is_mitogen:
                executor_result._get_connection = get_connection_method

        else:
            if self._shared_loader_obj.action_loader.has_plugin(module_name, None):
                task = self._task.copy()
                task.load_data({
                    'action': module_name,
                    'args': module_args,
                })
                handler = self._shared_loader_obj.action_loader.get(
                    module_name,
                    task=task,
                    connection=self._connection,
                    play_context=self._play_context.set_task_and_variable_override(task, {}, self._templar),
                    loader=self._loader,
                    templar=self._templar,
                    shared_loader_obj=self._shared_loader_obj,
                    collection_list=None
                )

                ret = handler.run(None, self._task_vars)

            else:
                ret = self._execute_module(module_name, module_args, None, self._task_vars,
                                           persist_files, delete_remote_tmp, wrap_async)

        self._check_result(module_name, run_on_ca_host, ret, ignore_changed, ignore_failed)
        return ret

    def _execute_openssl_module(self, name, args, **kwargs):
        ActionModule._update(args, {'select_crypto_backend': self._var("select_crypto_backend")}),
        return self.__execute_module(name, args, **kwargs)

    def _execute_command(self, command, run_on_ca_host=False, ignore_failed=False):
        if run_on_ca_host:
            ret = self.__execute_module("command", {
                'cmd': command
            }, run_on_ca_host=True, ignore_failed=ignore_failed, ignore_changed=True)

        else:
            ret = self._connection.exec_command(command)

            if not ignore_failed and ret[0] != 0:
                raise AnsibleError("Command '{0}' failed, return_value: {1}, output: {2}".format(
                    command, ret[0], ret[1]
                ))

            ret = {
                "rc": ret[0],
                "stdout": ret[1].decode("utf-8"),
                "stderr": ret[2].decode("utf-8")
            }

        return ret

    @staticmethod
    def _update(o_dict, u_dict):
        for k, v in u_dict.items():
            if k in o_dict and isinstance(v, dict):
                ActionModule._update(o_dict[k], v)
            else:
                o_dict[k] = v

    @staticmethod
    def _get_subject_dict(subject_ordered):
        subject = {}

        for v in subject_ordered:
            if not v[0] in subject:
                subject[v[0]] = []
            subject[v[0]].append(v[1])

        return subject

    def _translate_subject_dict(self, subject):
        new_subject = {}

        for k, v in subject.items():
            new_subject[NORMALIZE_NAMES.get(k)] = v

        return new_subject

    @staticmethod
    def _ansible_mapping_to_dict(amap):
        if isinstance(amap, AnsibleMapping):
            amap = dict(amap)

        if isinstance(amap, dict):
            for k, v in amap.items():
                amap[k] = ActionModule._ansible_mapping_to_dict(v)

        return amap

    def _x509_name_compare(self, d1, d2, errors, name_type):
        keys = set(d1.keys())
        keys.update(d2.keys())

        for name in keys:
            d1_val = ""
            d2_val = ""

            if name in d1:
                d1_val = d1[name]

            if name in d2:
                d2_val = d2[name]

            if not isinstance(d1_val, list):
                d1_val = [d1_val]

            if not isinstance(d2_val, list):
                d2_val = [d2_val]

            if ActionModule._compare_dict(d1_val, d2_val):
                errors.append("Certificate's {0} {1} doesn't match, '{2}' != '{3}'".format(
                    name_type, name, ', '.join(d1_val), ', '.join(d2_val)
                ))

    def _convert_x509_extension_names(self, extensions):
        if not isinstance(extensions, list):
            return []

        converted_extensions = []

        for ext in extensions:
            if ext in self._X509_key_usage_name_map:
                converted_extensions.append(self._X509_key_usage_name_map[ext])

            else:
                converted_extensions.append(ext)

        return converted_extensions

    @staticmethod
    def _compare_dict(_dict1, _dict2):
        dict1 = frozenset(_dict1)
        dict2 = frozenset(_dict2)

        return len(dict1) != len(dict2) or len(dict1.intersection(dict2)) != len(dict1)

    @staticmethod
    def _unique_list(_list):
        seen = set()
        return [x for x in _list if not (x in seen or seen.add(x))]

    # noinspection PyTypeChecker
    def _ensure_ca_private_key_path(self):
        if self._ca_var("private_key_path"):
            return

        if self._ca_var("private_key") is None:
            raise AnsibleError("CA private key not set")

        self._vars['ca']['private_key_path'] = self._local_temp + "/ca.key"
        self._copy_content(
            self._ca_var("private_key"),
            self._ca_var("private_key_path"),
            ignore_changed=True,
            run_on_ca_host=True
        )

    # =============== Action/Module Wrappers ===============

    def _create_temp_folder(self, **kwargs):
        temp_dir = self.__execute_module("tempfile", {"state": "directory", "prefix": "ansible.mgssl."}, **kwargs)
        return temp_dir['path']

    def _stat(self, path, **kwargs):
        return self.__execute_module("stat", {"path": path}, **kwargs)

    def _file_exists(self, path, **kwargs):
        return self._stat(path, **kwargs)['stat']['exists']

    def _fetch(self, src, dest, **kwargs):
        return self.__execute_module("fetch", {"src": src, "dest": dest, "flat": True}, **kwargs)

    def _remove_file(self, path, **kwargs):
        return self.__execute_module("file", {"path": path, "state": "absent"}, **kwargs)

    def _set_file_mode(self, path, mode, **kwargs):
        return self.__execute_module("file", {"path": path, "mode": mode}, **kwargs)

    def _copy(self, src, dest, force=False, **kwargs):
        return self.__execute_module("copy", {"src": src, "dest": dest, "force": force}, **kwargs)

    def _copy_content(self, content, dest, force=False, **kwargs):
        return self.__execute_module("copy", {"content": content, "dest": dest, "force": force}, **kwargs)

    def _slurp(self, path, **kwargs):
        return b64decode(self.__execute_module("slurp", {"src": path}, **kwargs)['content'])

    def _openssl_certificate_info(self, _path, valid_at=None):
        module_vars = {"path": _path}

        if valid_at is not None:
            module_vars["valid_at"] = {"assert": valid_at}

        cert_info = self._execute_openssl_module(
            "openssl_certificate_info",
            module_vars,
            run_on_ca_host=True,
            ignore_changed=True
        )

        return cert_info

    # =============== Executing Methods ===============

    def _precheck(self):
        if not NORMALIZE_NAMES_FOUND:
            raise AnsibleError('NORMALIZE_NAMES not found in either cryptography support or crypto_utils')

    def _main(self):
        self._remote_temp = self._create_temp_folder(ignore_changed=True)
        self._local_temp = self._create_temp_folder(run_on_ca_host=True, ignore_changed=True)

        self._load_ca()

        if self._var("force"):
            self._invalid_cert("Force certificate generation")

        else:
            key_exists = self._file_exists(self._var("private_key_path"), ignore_changed=True)
            cert_exists = self._file_exists(self._var("cert_path"), ignore_changed=True)

            if not key_exists or not cert_exists:
                self._invalid_cert("Certificate and/or key not found.")
                return

        self._fetch(self._var("cert_path"), self._local_temp + "/my_cert.pem", ignore_changed=True)

        errors = self._check_certificate()
        if len(errors) != 0:
            self._invalid_cert("Certificate check failed:\n{0}".format('\n'.join(errors)))
            return

        if not self._check_remote_certificate():
            self._invalid_cert("Remote certificate check failed.")

        if (self._var_opt("ca_cert_path") is not None and
                not self._file_exists(self._var("ca_cert_path"), ignore_changed=True)):
            self._copy_ca_certificate()

        if (self._var_opt("fullchain_cert_path") is not None and
                not self._file_exists(self._var("fullchain_cert_path"), ignore_changed=True)):
            self._copy_fullchain_certificate()

    def _invalid_cert(self, reason):
        if self._check_mode:
            self._changed = True
            raise CheckModeChanged(reason)

        if not self._var("enable_cert_creation"):
            raise AnsibleError(reason + "\nCertificate generation disabled")

        self._generate_certificate()

        errors = self._check_certificate()
        if len(errors) != 0:
            self._invalid_cert("Certificate check failed for newly created certificate: {0}".format('\n'.join(errors)))
            return

        if not self._check_remote_certificate():
            raise AnsibleError("Remote certificate check failed for newly created certificate")

    # noinspection PyTypeChecker
    def _check_certificate(self):
        cert_info = self._openssl_certificate_info(self._local_temp + "/my_cert.pem", self._profile_var("valid_at"))

        errors = []
        _assert = self._var("assert")

        if _assert['signature_algorithm'] and cert_info["signature_algorithm"] not in _assert['signature_algorithm']:
            errors.append("Signature algorithm not in valid list: {0}".format(cert_info['signature_algorithm']))

        if _assert["subject"]:
            self._x509_name_compare(
                self._translate_subject_dict(self._var("subject")),
                ActionModule._get_subject_dict(cert_info['subject_ordered']),
                errors,
                "subject"
            )

        if _assert['issuer']:
            self._x509_name_compare(
                ActionModule._get_subject_dict(self._ca_info['subject_ordered']),
                ActionModule._get_subject_dict(cert_info['issuer_ordered']),
                errors,
                "issuer"
            )

        if _assert['expired'] and cert_info['expired']:
            errors.append("Certificate expired")

        if _assert['valid_at'] and not cert_info['valid_at']['assert']:
            errors.append("Certificate not valid at '{0}'".format(self._profile_var("valid_at")))

        if _assert['version'] and cert_info['version'] != _assert['version']:
            errors.append("Certificate version doesn't match")

        if _assert['key_usage']:
            cert_key_usages = self._convert_x509_extension_names(cert_info['key_usage'])
            csr_key_usages = self._profile_var("key_usage", [])

            if ActionModule._compare_dict(cert_key_usages, csr_key_usages):
                errors.append("Certificate key usage doesn't match: '{0}' != '{1}'".format(
                    ','.join(cert_key_usages), ','.join(csr_key_usages)
                ))

        if _assert['key_usage_critical'] and cert_info['key_usage_critical'] != self._profile_var('key_usage_critical'):
            errors.append("Certificate key usage critical doesn't match")

        if _assert['extended_key_usage']:
            cert_ext_key_usages = []
            if cert_info['extended_key_usage'] is not None:
                for i in range(0, len(cert_info['extended_key_usage'])):
                    cert_info['extended_key_usage'][i] = NORMALIZE_NAMES_SHORT.get(
                        cert_info['extended_key_usage'][i], cert_info['extended_key_usage'][i]
                    )

                cert_ext_key_usages = cert_info['extended_key_usage']

            csr_ext_key_usages = self._profile_var("extended_key_usage", [])

            if ActionModule._compare_dict(cert_ext_key_usages, csr_ext_key_usages):
                errors.append("Certificate extended key usage doesn't match: '{0}' != '{1}'".format(
                    ','.join(cert_ext_key_usages), ','.join(csr_ext_key_usages))
                )
        if (_assert['extended_key_usage_critical'] and
                cert_info['extended_key_usage_critical'] != self._profile_var('extended_key_usage_critical')):
            errors.append("Certificate extended key usage critical doesn't match")

        if _assert['san']:
            csr_san = []

            var_san = self._var_opt("SANs")
            if var_san is None or len(var_san) == 0:
                csr_san.append("DNS:" + self._var("subject")['CN'])

            csr_san.extend(self._var_opt("SANs") or [])

            if ActionModule._compare_dict(cert_info['subject_alt_name'] or [], csr_san):
                errors.append("Certificate SAN doesn't match: '{0}' != '{1}'".format(
                    ','.join(cert_info['subject_alt_name'] or []), ','.join(csr_san))
                )

        if _assert['san_critical'] and cert_info['subject_alt_name_critical'] != self._profile_var('san_critical'):
            errors.append("Certificate SAN critical doesn't match")

        return errors

    def _clean_up(self):
        if self._remote_temp is not None:
            self._remove_file(self._remote_temp, ignore_changed=True)

        if self._local_temp is not None:
            self._remove_file(self._local_temp, ignore_changed=True)

    def _generate_certificate(self):
        # Generate private key on remote host
        params = {
            "path": self._var("private_key_path"),
            "size": self._var("private_key_length"),
            "type": self._var("private_key_type"),
            "mode": self._var("private_key_mode"),
            "force": True
        }

        curve = self._var_opt("private_key_curve")
        if curve is not None:
            params["curve"] = curve

        self._execute_openssl_module("openssl_privatekey", params)

        # Generate csr on remote host
        self._execute_openssl_module("openssl_csr", {
            "path": self._remote_temp + "/my_csr.csr",
            "privatekey_path": self._var("private_key_path"),
            "subject": self._var("subject"),
            "key_usage": ActionModule._unique_list(self._profile_var("key_usage") or []),
            "key_usage_critical": self._profile_var("key_usage_critical"),
            "extended_key_usage": ActionModule._unique_list(self._profile_var("extended_key_usage") or []),
            "extended_key_usage_critical": self._profile_var("extended_key_usage_critical"),
            "subject_alt_name": ActionModule._unique_list(self._var_opt("SANs") or []),
            "subject_alt_name_critical": self._profile_var("san_critical"),
            "force": True
        })

        # Fetch csr
        self._fetch(self._remote_temp + "/my_csr.csr", self._local_temp + "/my_csr.csr")

        # Remove csr on remote host
        self._remove_file(self._remote_temp + "/my_csr.csr")

        # Create certificate
        self._ensure_ca_private_key_path()
        self._execute_openssl_module("openssl_certificate", {
            "path": self._local_temp + "/my_cert.pem",
            "csr_path": self._local_temp + "/my_csr.csr",
            "ownca_path": self._ca_var("certificate_path"),
            "ownca_privatekey_path": self._ca_var("private_key_path"),
            "ownca_not_after": self._profile_var("expiry"),
            "provider": "ownca",
            "force": True
        }, run_on_ca_host=True)

        # Check if new certificate is valid
        errors = self._check_certificate()
        if len(errors) != 0:
            raise AnsibleError("Validation of generated certificate failed: {0}".format('\n'.join(errors)))

        # Copy certificate to remote host
        self._copy(self._local_temp + "/my_cert.pem", self._var("cert_path"), True)
        self._set_file_mode(self._var("cert_path"), self._var("cert_mode"))

        # Archive certificate
        if self._var_opt("archive_dir_path") is not None:
            cert_info = self.__execute_module("openssl_certificate_info", {
                "path": self._local_temp + "/my_cert.pem"
            }, run_on_ca_host=True)

            archive_dir_path = self._var("archive_dir_path")
            self.__execute_module("file", {
                "path": archive_dir_path,
                "state": "directory"
            }, run_on_ca_host=True)

            self._copy(
                self._local_temp + "/my_cert.pem",
                archive_dir_path + "/" + (hex(cert_info['serial_number'])[2:].upper()) + ".pem",
                run_on_ca_host=True
            )

        if self._var_opt("archive_path") is not None:
            self._copy(
                self._local_temp + "/my_cert.pem",
                self._var("archive_path"),
                True,
                run_on_ca_host=True
            )

        # Copy ca certificate to remote host
        self._copy_ca_certificate()

        # Copy fullchain certificate to remote host
        self._copy_fullchain_certificate()

    # noinspection PyTypeChecker
    def _check_remote_certificate(self):
        _assert = self._var("assert")

        if _assert['remote_private_key']:
            # Generate nonce
            nonce = b64encode(urandom(42))
            self._copy_content(nonce, self._remote_temp + "/rnd", ignore_changed=True)
            self._copy_content(nonce, self._local_temp + "/rnd", run_on_ca_host=True, ignore_changed=True)

            # Sign nonce
            sig = self._execute_openssl_module("community.crypto.openssl_signature", {
                'privatekey_path': self._var("private_key_path"),
                'path': self._remote_temp + '/rnd',
            }, ignore_changed=True)

            ret = self._execute_openssl_module("community.crypto.openssl_signature_info", {
                'certificate_path': self._local_temp + "/my_cert.pem",
                'path': self._local_temp + '/rnd',
                'signature': sig['signature'],
            }, ignore_changed=True, run_on_ca_host=True, ignore_failed=True)

            if ('failed' in ret and ret['failed']) or not ret['valid']:
                return False

        # Verify that the cert is issued by the ca cert
        openssl_path_prefix = ""
        if system() == "Darwin":
            openssl_path_prefix = self._get_macos_openssl_path()

        ret = self._execute_command("{0}openssl verify -verbose -partial_chain -CAfile {1} {2}/my_cert.pem".format(
            openssl_path_prefix,
            self._ca_var("certificate_path"),
            self._local_temp
        ), run_on_ca_host=True)

        return ret['stdout'].rstrip().endswith('OK')

    def _get_macos_openssl_path(self):
        """Make an educated guess about Homebrew provided OpenSSL@1.1 path for macOS.

        Supports both Intel and Apple Silicon using the homebrew prefix.
        """
        homebrew_path = ""

        result =  self._execute_command("brew config", True)
        if result['rc'] != 0:
            raise AnsibleError("Could not use homebrew config to determine HOMEBREW_PREFIX. Unable to provide path to OpenSSL and LibreSSL is not supported.")

        for line in result['stdout'].splitlines():
            if line.startswith("HOMEBREW_PREFIX"):
                homebrew_path =  line.split(':')[1].strip()
                break

        return os.path.join(homebrew_path, 'opt/openssl@1.1/bin/')

    # noinspection PyTypeChecker
    def _load_ca(self):
        if self._ca_var("certificate_path") is None and self._ca_var("private_key_path") is None:
            if self._var_opt("ca_config_path") is not None:
                ret = self.__execute_module("include_vars", {
                    'name': 'ca',
                    'file': self._var("ca_config_path")
                }, run_on_ca_host=True, ignore_changed=True)

                ActionModule._update(
                    self._vars['ca'],
                    ActionModule._ansible_mapping_to_dict(ret['ansible_facts']['ca'])
                )

                if 'profiles' in self._vars['ca']:
                    ActionModule._update(self._vars['profiles'], self._ca_var("profiles"))
                    del self._vars['ca']['profiles']

            if self._ca_var("certificate") is not None:
                self._vars['ca']['certificate_path'] = self._local_temp + "/ca.pem"
                self._copy_content(
                    self._ca_var("certificate"),
                    self._ca_var("certificate_path"),
                    ignore_changed=True,
                    run_on_ca_host=True
                )

            if self._ca_var("private_key") is not None:
                # Only write private key if required
                self._vars['ca']['private_key_path'] = False

        errors = []

        if self._ca_var("certificate_path") is None:
            errors.append("CA Certificate missing")

        if self._ca_var("private_key_path") is None:
            errors.append("CA Private Key missing")

        if len(errors) != 0:
            raise AnsibleError("\n".join(errors))

        self._copy_content(
            self._ca_var("certificate"),
            self._local_temp + "/ca.crt",
            run_on_ca_host=True,
            ignore_changed=True
        )

        self._ca_info = self._openssl_certificate_info(
            self._local_temp + "/ca.crt",
            self._ca_var("valid_at")
        )

        _assert = self._var("assert")

        if _assert['ca_expired'] is not None and self._ca_info['expired']:
            raise AnsibleError("CA Certificate expired")

        if _assert['valid_at'] is not None and not self._ca_info['valid_at']['assert']:
            raise AnsibleError("Certificate not valid at '{0}'".format(self._ca_var("valid_at")))

    def _copy_ca_certificate(self):
        if self._var_opt("ca_cert_path") is not None:
            self._copy(self._ca_var("certificate_path"), self._var("ca_cert_path"), True)
            self._set_file_mode(self._var("ca_cert_path"), self._var("cert_mode"))

    def _copy_fullchain_certificate(self):
        if self._var_opt("fullchain_cert_path") is not None:
            cert = self._slurp(self._local_temp + "/my_cert.pem", run_on_ca_host=True)
            ca = self._slurp(self._ca_var("certificate_path"), run_on_ca_host=True)

            self._copy_content(cert + ca, self._var("fullchain_cert_path"), True)
            self._set_file_mode(self._var("fullchain_cert_path"), self._var("cert_mode"))
