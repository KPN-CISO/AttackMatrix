# MITRE ATT&CK API

## Introduction

AttackMatrix is a Python module to interact with and explore MITRE's ATT&CK's matrices.

## Features

AttackMatrix can be:

- loaded as a module;
- run as a daemon, providing an HTTP JSON API endpoint for querying;
- run as a standalone script for generating a Python dict of a chosen matrix for use in other software.

Loaded matrices can be queried through multiple functions and will return a Python dict or JSON object, depending on the runtime variant. The following examples assume a 'daemonized' instance:

- exploration of the *Enterprise* ATT&CK matrix to find information about the *Actor* *G0005*:
  -  http://.../api/explore/Enterprise/Actors/G0005
- searching all entities with the words *dragon*, *capture* **or** *property* in the *Enterprise* and *ICS* ATT&CK® matrices:
  - http://.../api/search/?params=dragon&params=capture&params=property&matrix=ICS&matrix=Enterprise
- finding the overlapping TTPs (*Malwares, Mitigations, Subtechniques, Techniques and Tools*) for the *actors G0064* and *G0050*. Returns a list of *Actors*, a list of *matrices* they were  found in, and only the *TTPs* that overlapped (with their names/descriptions):
  - http://.../api/actoroverlap/?actor1=G0064&actor2=G0050
- finding all actors that have a specific set of TTPs (*Malwares, Subtechniques, Techniques and Tools*). The number of TTPs is variable, i.e.: *1 ... n* fields can be given.  Returns the matching *Actors* with all of their ATT&CK entity  types (including names/descriptions):
  - http://.../api/ttpoverlap/?ttp=S0002&ttp=S0008&ttp=T1560.001

## Requirements

1. `Python` 3.5+ (uses modern dictionary merging)
2. `dpath` (usage is deprecated, requirement will be removed in future versions)
3. `Uvicorn`
4. `FastAPI`
5. At least one MITRE ATT&CK® matrix

## Installation

1. `git clone` the repository
2. Install the dependencies: `pip3 install -r requirements.txt`
3. Edit the configuration in `config/settings.py.sample` and save it as `config/settings.py`
4. [Optional] Edit the configuration in `config/matrixtable.py` to your liking
5. Read the help: `./attackmatrix.py -h`
6. Download, transform and cache at least one matrix (default: `Enterprise`) using `./attackmatrix.py -t ...`

## Comments and Suggestions

If you would like to reach out with ideas for improvements or general feedback, please reach out to the [author](mailto:arnime <remove-and-replace> kpn-cert.nl).

## Known issues

Yes, the code could be cleaner and more efficient - I'm not a professional developer okay :-)