# Third-Party Licenses

The PolyForm and commercial licensing paths cover only original material for which the repository licensor owns or controls the necessary rights. They do not replace or narrow third-party licenses.

## Direct upstream projects

| Component | Repository use | Upstream license | Source |
|---|---|---|---|
| SECFORCE LLMGoat | `docker/llmgoat/` runtime and directly importing course wrapper | GPL-3.0-only | Original: <https://github.com/SECFORCE/LLMGoat>, installation fork: <https://github.com/gasbugs/LLMGoat> |
| ReversecLabs Damn Vulnerable LLM Agent | `docker/dvla/` build and runtime | Apache-2.0 | <https://github.com/ReversecLabs/damn-vulnerable-llm-agent> |
| llama.cpp | `examples/llm03/Dockerfile.llama-cpp` build dependency | MIT | <https://github.com/ggml-org/llama.cpp> |

Files copied from, linked with, or derived from these projects must be used and distributed under the applicable upstream terms. In particular, every original file under `docker/llmgoat/` is expressly distributed under GPL-3.0-only as recorded in its `COPYING`; the repository-level PolyForm license does not apply to those files.

## Other dependencies

Container base images, Terraform and Packer providers, Python and Node.js packages, models, observability products, and command-line tools retain their own licenses and notices. Image tags, package manifests, lock files, Dockerfiles, and Terraform provider declarations identify the versions used by this repository.

This file is a scope notice, not a complete reproduction of every transitive dependency license. When distributing a built image or packaged artifact, include all notices and source-offer obligations required by the components actually included in that artifact.
