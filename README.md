# owdit

Audits nodejs dependencies for known vulnerabilities.

## Introduction

## Installation
```bash
> npm install -g owdit
```
`owdit` should preferably be installed globally.

## Usage
##### Command-line Usage
```bash
> owdit
```
When run from the command line, `owdit` will inspect the dependencies listed in `package.json` sitting in the current directory and will recursively audit the found dependencies.

When vulnerabilities are found, `owdit` prints out a pretty-formatted report.  
The exit code of `owdit` is the number of found vulnerabilities or _-1_ on error.

##### Programmatic Usage
```javascript
const owdit = require("owdit");
const util = require("util");

owdit.check(process.cwd(), (err, vulnerabilityReport) => {
  if (err) {
    console.error(err);
  } else {
    console.log(util.inspect(vulnerabilityReport, { depth: null }));
  }
}
```

## Credits
This work was inspired by:
* https://github.com/OSSIndex/auditjs
* https://github.com/nodesecurity/nsp

## License
[MIT](LICENSE)
