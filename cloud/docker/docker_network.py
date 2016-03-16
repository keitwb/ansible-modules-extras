#!/usr/bin/python

# (c) 2016, Ben Keith <ben.keith@quoininc.com>
#
# This file is part of Ansible
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

DOCUMENTATION = '''
---
module: docker_network
version_added: "2.2"
short_description: Manage Docker networks
description:
  - Create Docker networks and connect containers to them.
options:
  name:
    description:
      - The name of the docker network
    required: true
  containers:
    description:
      - A list of the names of the containers that should be connected to the network
    default: null
    required: false
  driver:
    description:
      - The network driver to use
    choices:
      - bridge
    default: bridge
    required: false
  state:
    description:
      - Assert the network's desired state.
    required: false
    default: present
    choices:
      - present
      - absent
  disconnect_missing:
    description:
      - Whether to disconnect any containers that are not in the list of
        containers for this network.  If false, then any previously connected
        containers will be left connected.
    default: 'false'
    required: false
  docker_url:
    description:
      - URL of docker host to issue commands to
    required: false
    default: ${DOCKER_HOST} or unix://var/run/docker.sock
    aliases: []
  use_tls:
    description:
      - Whether to use tls to connect to the docker server.  "no" means not to
        use tls (and ignore any other tls related parameters). "encrypt" means
        to use tls to encrypt the connection to the server.  "verify" means to
        also verify that the server's certificate is valid for the server
        (this both verifies the certificate against the CA and that the
        certificate was issued for that host. If this is unspecified, tls will
        only be used if one of the other tls options require it.
    choices: [ "no", "encrypt", "verify" ]
    version_added: "2.0"
  tls_client_cert:
    description:
      - Path to the PEM-encoded certificate used to authenticate docker client.
        If specified tls_client_key must be valid
    default: ${DOCKER_CERT_PATH}/cert.pem
    version_added: "2.0"
  tls_client_key:
    description:
      - Path to the PEM-encoded key used to authenticate docker client. If
        specified tls_client_cert must be valid
    default: ${DOCKER_CERT_PATH}/key.pem
    version_added: "2.0"
  tls_ca_cert:
    description:
      - Path to a PEM-encoded certificate authority to secure the Docker connection.
        This has no effect if use_tls is encrypt.
    default: ${DOCKER_CERT_PATH}/ca.pem
    version_added: "2.0"
  tls_hostname:
    description:
      - A hostname to check matches what's supplied in the docker server's
        certificate.  If unspecified, the hostname is taken from the docker_url.
    default: Taken from docker_url
    version_added: "2.0"
  docker_api_version:
    description:
      - Remote API version to use. This defaults to the current default as
        specified by docker-py.
    default: docker-py default remote API version
    version_added: "2.0"
author:
    - "Ben Keith (@keitwb)"
requirements:
    - "python >= 2.6"
    - "docker-py >= 1.5.0"
    - "The docker server >= 1.9.0"
'''

EXAMPLES = '''
Containers must be present before they can be connected.

Create a bridged network named 'backend' with containers 'app' and
'database' connected to it

- name: Create database network
  docker_network:
    name: backend
    containers:
      - app
      - database
    state: present

If you want the list of containers to be the exclusive containers on the
specified network, then set 'disconnect_missing' to true.  This example will
disconnect the database container connected in the above example:

- name: Create database network
  docker_network:
    name: backend
    containers:
      - app
    disconnect_missing: true
    state: present

If disconnect_missing were set the false (the default), the database container
would be left connected to the network.

Removing networks is straightforward:

- name: Remove database network
  docker_network:
    name: backend
    state: absent
'''

RETURN = '''
msg:
  description: execution result of module
  type: string
  returned: success, failure
  sample: Network ansible-test2 created; Connected containers ansible-dev to network.
'''

HAS_DOCKER_PY = True
DEFAULT_DOCKER_API_VERSION = None


import sys
import json
import os
import shlex
from urlparse import urlparse
try:
    import docker.client
    import docker.utils
    import docker.errors
    from requests.exceptions import RequestException
except ImportError:
    HAS_DOCKER_PY = False

if HAS_DOCKER_PY:
    try:
        from docker.errors import APIError as DockerAPIError
    except ImportError:
        from docker.client import APIError as DockerAPIError
    try:
        # docker-py 1.2+
        import docker.constants
        DEFAULT_DOCKER_API_VERSION = docker.constants.DEFAULT_DOCKER_API_VERSION
    except (ImportError, AttributeError):
        # docker-py less than 1.2
        DEFAULT_DOCKER_API_VERSION = docker.client.DEFAULT_DOCKER_API_VERSION


def get_docker_py_versioninfo():
    if hasattr(docker, '__version__'):
        # a '__version__' attribute was added to the module but not until
        # after 0.3.0 was pushed to pypi. If it's there, use it.
        version = []
        for part in docker.__version__.split('.'):
            try:
                version.append(int(part))
            except ValueError:
                for idx, char in enumerate(part):
                    if not char.isdigit():
                        nondigit = part[idx:]
                        digit = part[:idx]
                        break
                if digit:
                    version.append(int(digit))
                if nondigit:
                    version.append(nondigit)
    elif hasattr(docker.Client, '_get_raw_response_socket'):
        # HACK: if '__version__' isn't there, we check for the existence of
        # `_get_raw_response_socket` in the docker.Client class, which was
        # added in 0.3.0
        version = (0, 3, 0)
    else:
        # This is untrue but this module does not function with a version less
        # than 0.3.0 so it's okay to lie here.
        version = (0,)

    return tuple(version)


def check_dependencies(module):
    """
    Ensure `docker-py` >= 1.5.0 is installed, and call module.fail_json with a
    helpful error message if it isn't.
    """
    if not HAS_DOCKER_PY:
        module.fail_json(msg="`docker-py` doesn't seem to be installed, but is required for the Ansible Docker module.")
    else:
        versioninfo = get_docker_py_versioninfo()
        if versioninfo < (1, 5, 0):
            module.fail_json(msg="The Ansible Docker module requires `docker-py` >= 1.5.0.")


class DockerNetworkManager(object):

    def __init__(self, module):
        self.module = module

        self.network_name = self.module.params.get('name', None)
        self.container_names = self.module.params.get('containers', [])
        self.driver = self.module.params.get('driver', None)

        self.network_created = False
        self.network_removed = False
        self.containers_connected = []
        self.containers_disconnected = []

        # Connect to the docker server using any configured host and TLS settings.

        env_host = os.getenv('DOCKER_HOST')
        env_docker_verify = os.getenv('DOCKER_TLS_VERIFY')
        env_cert_path = os.getenv('DOCKER_CERT_PATH')
        env_docker_hostname = os.getenv('DOCKER_TLS_HOSTNAME')

        docker_url = module.params.get('docker_url')
        if not docker_url:
            if env_host:
                docker_url = env_host
            else:
                docker_url = 'unix://var/run/docker.sock'

        docker_api_version = module.params.get('docker_api_version')

        tls_client_cert = module.params.get('tls_client_cert', None)
        if not tls_client_cert and env_cert_path:
            tls_client_cert = os.path.join(env_cert_path, 'cert.pem')

        tls_client_key = module.params.get('tls_client_key', None)
        if not tls_client_key and env_cert_path:
            tls_client_key = os.path.join(env_cert_path, 'key.pem')

        tls_ca_cert = module.params.get('tls_ca_cert')
        if not tls_ca_cert and env_cert_path:
            tls_ca_cert = os.path.join(env_cert_path, 'ca.pem')

        tls_hostname = module.params.get('tls_hostname')
        if tls_hostname is None:
            if env_docker_hostname:
                tls_hostname = env_docker_hostname
            else:
                parsed_url = urlparse(docker_url)
                if ':' in parsed_url.netloc:
                    tls_hostname = parsed_url.netloc[:parsed_url.netloc.rindex(':')]
                else:
                    tls_hostname = parsed_url
        if not tls_hostname:
            tls_hostname = True

        # use_tls can be one of four values:
        # no: Do not use tls
        # encrypt: Use tls.  We may do client auth.  We will not verify the server
        # verify: Use tls.  We may do client auth.  We will verify the server
        # None: Only use tls if the parameters for client auth were specified
        #   or tls_ca_cert (which requests verifying the server with
        #   a specific ca certificate)
        use_tls = module.params.get('use_tls')
        if use_tls is None and env_docker_verify is not None:
            use_tls = 'verify'

        tls_config = None
        if use_tls != 'no':
            params = {}

            # Setup client auth
            if tls_client_cert and tls_client_key:
                params['client_cert'] = (tls_client_cert, tls_client_key)

            # We're allowed to verify the connection to the server
            if use_tls == 'verify' or (use_tls is None and tls_ca_cert):
                if tls_ca_cert:
                    params['ca_cert'] = tls_ca_cert
                    params['verify'] = True
                    params['assert_hostname'] = tls_hostname
                else:
                    params['verify'] = True
                    params['assert_hostname'] = tls_hostname
            elif use_tls == 'encrypt':
                params['verify'] = False

            if params:
                # See https://github.com/docker/docker-py/blob/d39da11/docker/utils/utils.py#L279-L296
                docker_url = docker_url.replace('tcp://', 'https://')
                tls_config = docker.tls.TLSConfig(**params)

        self.client = docker.Client(base_url=docker_url,
                                    version=docker_api_version,
                                    tls=tls_config)

        self.docker_py_versioninfo = get_docker_py_versioninfo()

        self.existing_network = self.get_existing_network()

    def has_changed(self):
        return bool(self.network_created or self.containers_connected)

    def get_summary_message(self):
        '''
        Generate a message that briefly describes the actions taken by this
        task, in English.
        '''
        parts = []
        if self.network_created:
            parts.append("Network %s created" % self.network_name)
        elif self.network_removed:
            parts.append("Network %s removed" % self.network_name)

        if self.containers_connected:
            parts.append("Connected containers %s to network" %
                         ', '.join(self.containers_connected))

        if self.containers_disconnected:
            parts.append("Disconnected containers %s from network" %
                         ', '.join(self.containers_disconnected))

        if parts:
            return '; '.join(parts) + '.'
        else:
            return "No action taken."

    def get_existing_network(self):
        networks = self.client.networks()
        for n in networks:
            if n['Name'] == self.network_name:
                return n

    def create_network(self):
        if not self.existing_network:
            resp = self.client.create_network(self.network_name, driver=self.driver)
            self.existing_network = self.client.inspect_network(resp['Id'])
            self.network_created = True

    def remove_network(self):
        if self.existing_network:
            self.disconnect_all_containers()
            self.client.remove_network(self.network_name)
            self.network_removed = True

    def is_container_connected(self, container_name):
        container_names = [c['Name'] for c in self.existing_network['Containers'].values()]
        return container_name in container_names

    def connect_containers(self):
        for name in self.container_names:
            if not self.is_container_connected(name):
                self.client.connect_container_to_network(name, self.network_name)
                self.containers_connected.append(name)

    def disconnect_missing(self):
        for c in self.existing_network['Containers'].values():
            name = c['Name']
            if name not in self.container_names:
                self.client.disconnect_container_from_network(name,
                                                              self.network_name)
                self.containers_disconnected.append(name)

    def disconnect_all_containers(self):
        containers = self.client.inspect_network(self.network_name)['Containers']
        for cont in containers.values():
            self.client.disconnect_container_from_network(cont['Name'], self.network_name)
            self.containers_disconnected.append(cont['Name'])


def present(manager, disconnect_missing):
    manager.create_network()
    manager.connect_containers()
    if disconnect_missing:
        manager.disconnect_missing()


def absent(manager):
    manager.remove_network()


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name               = dict(required=True),
            state              = dict(default='present', choices=['present', 'absent']),
            driver             = dict(default='bridge', choices=['bridge']),
            disconnect_missing = dict(default=False, type='bool'),
            containers         = dict(default=[], type='list'),
            docker_url         = dict(),
            use_tls            = dict(default=None, choices=['no', 'encrypt', 'verify']),
            tls_client_cert    = dict(required=False, default=None, type='str'),
            tls_client_key     = dict(required=False, default=None, type='str'),
            tls_ca_cert        = dict(required=False, default=None, type='str'),
            tls_hostname       = dict(required=False, type='str', default=None),
            docker_api_version = dict(required=False, default=DEFAULT_DOCKER_API_VERSION, type='str'),
        ),
    )

    check_dependencies(module)

    try:
        manager = DockerNetworkManager(module)

        state = module.params.get('state')
        if state == 'present':
            present(manager, module.params.get('disconnect_missing'))
        elif state == 'absent':
            absent(manager)
        else:
            module.fail_json(msg='Unrecognized state %s. Must be one of: '
                                 'present; absent.' % state)

        module.exit_json(changed=manager.has_changed(),
                         msg=manager.get_summary_message())

    except DockerAPIError as e:
        module.fail_json(changed=manager.has_changed(), msg="Docker API Error: %s" % e.explanation)

    except RequestException as e:
        module.fail_json(changed=manager.has_changed(), msg=repr(e))

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
