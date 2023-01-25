# MITRE ATT&CK API 2.0

## Introduction

AttackMatrix API is a Python module to interact with and explore MITRE's ATT&CK® matrices.

## Changelog

Version 2 improves on the original version:

- Initial cache generation time is now *seconds*(!) instead of minutes.
- Occasional 'overlap' bugs should be fixed.
- Code has been greatly simplified/improved to simplify MITRE ATT&CK parsing and lay some groundwork for upcoming features.
- All ATT&CK matrices are now merged into a single searchable tree, with presence in matrices noted in its `Matrices` property. Consequently, queries are now 'matrix-agnostic' and may yield more (interesting) results.
- Tree structure is now consistent:
  - `Metadata` list() field for names, descriptions, urls.
  - First level results are already sensible MITRE entities.
  - Subkey/-value pair levels are predictable: unfolded key/value pairs always reveal first-level relationships.

## Notes

- Webgrapher is currently broken. I may fix it at some point the future. Currently, [MatterBot](https://github.com/uforia/MatterBot) may be able to provide you with the necessary graphs as well.
- Both **deprecated and 1.0 API** interfaces have been removed!
- You will need to update your code if you are using the old API endpoints.
- This is 'point-zero' release, so many bugs and edge-cases may pop up soon. Expect additional updates/patches!

## Licensing

- AttackMatrix and WebGrapher: GPLv3
- [https://d3js.org](D3.js): BSD
- [https://github.com/dagrejs/dagre-d3](dagre-d3): MIT
- [https://jquery.com/](jQuery): MIT
- [https://github.com/jaz303/tipsy](tipsy): MIT

## Features

AttackMatrix can be:

- loaded as a module;
- run as a daemon, providing an HTTP JSON API endpoint for querying;
- run as a standalone script for generating a Python dict of a chosen matrix for use in other software.

The API offers an endpoint where loaded matrices can be queried through multiple functions. The API will return a Python dict or JSON object, depending your runtime invocation. Visit the API endpoint's root '/' for automatic OpenAPI documentation.

## WebGrapher

The WebGrapher is currently broken and needs to be updated to use the new 2.0 interface.

## Requirements

### For the API

1. `Python` 3.5+ (uses modern dictionary and `collections` features)
2. `Uvicorn`
3. `FastAPI`
4. At least one MITRE ATT&CK® matrix

### For the WebGrapher

1. D3.js (included)
2. dagre-d3 (included)
3. tispy.js/.css (included)
4. A PHP-enabled webserver (Apache, nginx, ...)
5. `allow_furl_open` support enabled in the `php.ini` file: the script needs to be able to call the API endpoint

## Installation

### For the API

1. `git clone` the repository
2. Install the dependencies: `pip3 install -r requirements.txt`
3. Edit the configuration in `config/settings.py.sample` and save it as `config/settings.py`
4. [Optional] Edit the configuration in `config/matrixtable.py` to your liking
5. Read the help: `./attackmatrix.py -h`
6. Download, transform and cache at least one matrix (default: `Enterprise`) using `./attackmatrix.py -t ...`

### For the WebGrapher

1. `git clone` the repository
2. Place the `attackmap.php`, `d3.v5.min.js` and `dagre-d3.min.js` in a webserver-accessible directory with PHP-support enabled
3. Edit the `attackmap.php` file and change the `$api = '...'` URL. Please note: you can theoretically keep using the public AttackMatrix API (the `http://149.210...` host), but I reserve the right to block abuse, change the API endpoint functionality or take down the public API without prior notice.

## Comments and Suggestions

If you have ideas for improvements or general feedback, please reach out to the [author](mailto:uforia@dhcp.net).

## Known issues

The Webgrapher needs fixing. I'm not a professional webdeveloper, okay!? :-)

## Thanks

- MITRE, obviously, for their outstanding work on and sharing of ATT&CK - [MITRE® ATT&CK](https://attack.mitre.org)
- D3.js' outstanding Javascript visualization/rendering library - [D3.js](https://d3js.org)
- dagre-d3, for making D3.js understandable enough for me! - [dagre-d3](https://github.com/dagrejs/dagre-d3)
