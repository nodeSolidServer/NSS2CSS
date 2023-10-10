# Copy NSS pods to CSS
This [zero-dependency script for Node.js](https://github.com/RubenVerborgh/NSS2CSS/blob/main/copy-pods-to-css.mjs)
copies all pods
from a [Node Solid Server (NSS)](https://github.com/nodeSolidServer/node-solid-server) instance
into a [Community Solid Server (CSS)](https://github.com/CommunitySolidServer/CommunitySolidServer) instance.

## Prerequisites
- File access to the configuration and data of an NSS instance (tested with v5.7.7)
- File and HTTP access to the configuration and data of a CSS instance (compatible with v7.x)

## Running the script
```shell
./copy-pods-to-css.mjs nss/config.json css/data/ https://css.pod/ xxx@users.css.pod
```
where:
- `nss/config.json` is the file path to the NSS configuration file
- `css/data/` is the file path the CSS data folder
- `https://css.pod/` is the URL to the running CSS instance
- `xxx@users.css.pod` is the template for CSS usernames, where `xxx` is the old NSS username

## Functionality
This script:
- Creates one CSS account for each NSS pod
  - The username changes from `alice` to `alice@users.css.pod` (configurable)
  - The password remains the same
- Copies the contents of each NSS pod to the corresponding CSS pod
- Performs 2 tests per pod
  - Access the profile document (assumed public)
  - Access the inbox (assumed private)

## License
©2023 Ruben Verborgh – MIT License
