# Konflux integration test cases
As RedHat uses Konflux to build, verify and release containers now, all fdo containers will be built in konflux. The integration test cases defined in this folder will be triggered by konflux when new fdo container images are built.

## How konflux trigger test cases
konflux defines integration test workflow in this file: (when writing this doc, below files are not merged into konflux yet, will update it later)
- https://gitlab.cee.redhat.com/releng/konflux-release-data/-/merge_requests/2167/diffs#3904e36f53d22f073f197dedd0bd6355289a0053

Within this file, it defines fdo repo url and test file path:
- fdo repo: https://gitlab.cee.redhat.com/releng/konflux-release-data/-/merge_requests/2167/diffs#3904e36f53d22f073f197dedd0bd6355289a0053_0_15
- test file: https://gitlab.cee.redhat.com/releng/konflux-release-data/-/merge_requests/2167/diffs#3904e36f53d22f073f197dedd0bd6355289a0053_0_19

When konflux trigger integration test workflow, it will go to fdo repo and get the test file, and execute the tasks defined in test file.

## Test files in this folder
There are four pipeline files and one test file in this folder.
- fdo-manufacturing-server-integration-tests.yaml
- fdo-owner-onboarding-server-integration-tests.yaml
- fdo-rendezvous-server-integration-tests.yaml
- fdo-serviceinfo-api-server-integration-tests.yaml
- fdo-container-test.yaml

## Test case definition (manufacturing server test case as example)
There are two yaml files for manufacturing server test.

- fdo-manufacturing-server-integration-tests.yaml: This is the test file defined in konflux integration test workflow file, this file defines parameters, env variables and tasks. It also defines a task file path and pass all the parameters to that task file.
  Example of parameters:
  - SNAPSHOT: a parameter from konflux, it is basically the description of container that was built.
  - GIT_URL: tell konflux which git repo to get
  - GIT_REF: tell konflux which branch to use

- fdo-container-test.yaml: This is the task file that defined in fdo-manufacturing-server-integration-tests.yaml, it defines some actions:
  - get secrets from konflux
  - set parameters
  - get the url of fdo container we want to test
  - run bash script

## How to get fdo container
In task yaml file, we can use parameter SNAPSHOT to retrieve container image url, the returned value will be like quay.io/fido-fdo/serviceinfo-api-server
- IMAGE=$(echo "${SNAPSHOT}" | jq -r ".components[]|select(.name==\"$COMPONENT\")|.containerImage")

## How to set test runner
In task yaml file, we can specify the os and version of test runner to execute all the actions.
Set image like this, "- image: quay.io/testing-farm/cli:latest"
- It means to use the latest testing-farm cli container as runner, the benefit is that if you want to reserve a testing-farm machine to run test cases, you can use testing-farm command directly in script section and no need to install testing-farm related packages. 
- If you want to run test cases in this runner directly, just write all test cases in script section.
  
Depends on the os of test runner, you need to use different commands in bash script.
  - For testing-farm runner, run apk to install packages
  - For RHEL, Centos-Stream, Fedora, run dnf or yum to install packages.




