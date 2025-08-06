# VCF Automation Token Andible Module

This is a simple module for ansible that will use a VCF Automation token and return an access token that can then be used in other modules such as the kubernetes module to connect to the VCF-A IaaS APIs.

## Usage

1. Install the module into your modules library


2. add a task to your playbook

```yaml
tasks:
  - name: Get access token from VCFA
    vcfa_auth:
      vcfa_host: "vcf-a.vcf.lab"
      token: "LpIBk1Ed2K429c8rn8Nb8598je3sZC6M"
      tenant: "will-org"
      insecure: true
    register: token_output
```


## Testing

1. set the ansible module library to the current dir

```bash
export ANSIBLE_LIBRARY=./ 
```

2. run the playbook

```bash
ansible-playbook sample-playbook.yml 
```