const exec = require("executive");
const formatter = require("./formatters/default")
const Client = require("node-rest-client").Client;
const util = require("util");
const fs = require("fs");
const path = require("path");
const rcFilename = ".owditrc";

// Read from .owditrc the lists of packages that should be excluded or only generate warnings
function readWarnsAndExcludes(cwd) {
  let warns = [];
  let excludes = [];
  const rcFile = path.resolve(cwd, rcFilename);

  if (fs.existsSync(rcFile)) {
    try {
      const content = JSON.parse(fs.readFileSync(rcFile));

      warns = content.warns || [];
      excludes = content.excludes || [];
    } catch(err) {
      // Display any error occurred when reading or parsing .owditrc but don't stop the check.
      // At this moment, this file's sole purpose is to make the vulnerability check less strict.
      // Going on when there has been an error at this step means all vulnerabilities will be taken
      // into account and the check can only get stricter.
      console.log(err);
      console.log("Error reading or parsing .owditrc. All dependencies will be scanned.");
    }
  }

  if (warns.length) {
    console.log(`Vulnerabilities in these packages will only generate warnings: ${warns.join(", ")}.`)
  }
  if (excludes.length) {
    console.log(`Vulnerabilities in these packages will be IGNORED: ${excludes.join(", ")}.`)
  }

  return {warns, excludes};
}

module.exports.check = function(cwd, callback)
{
  const {warns, excludes} = readWarnsAndExcludes(cwd);

  const result = exec.sync("npm ls --production=true --json", { cwd: cwd, strict: true, quiet: true });
  if (result.status !== 0) {
    return callback(new Error("Error running npm ls: " + result.stderr));
  }
  let packages = [];
  try {
    packages = JSON.parse(result.stdout);
  } catch(err) {
    return callback(err);
  }

  let registerModules = {};
  function flattenDependencies(parentPackage, dependencies) {
    let list = [];
    let deps = Object.keys(dependencies);
    deps.forEach((dependency) => {
      if (excludes.includes(dependency)) {
        return;
      }
      const dependent = dependencies[dependency];
      const key = dependency + dependent.version;
      if (!registerModules.hasOwnProperty(key)) {
        const path = [...parentPackage, `${dependency}@${dependent.version}`];

        registerModules[key] = dependent;
        registerModules[key].path = path;
        list.push({ pm: "npm", name: dependency, version: dependent.version });
        if (dependent.dependencies) {
          list.push(...flattenDependencies(path, dependent.dependencies));
        }
      }
    });
    return list;
  }
  if (packages.dependencies) {
    const client = new Client();
    const flatList = flattenDependencies([`${packages.name}@${packages.version}`], packages.dependencies);
    const restOptions = {
        data: flatList,
        headers: { "Content-Type": "application/json" }
    };
    const request = client.post("https://ossindex.net/v2.0/package", restOptions, (data, response) => {
      let numVulnerabilitiesFails = 0;
      let numVulnerabilitiesWarns = 0;
      const vulnerablePackages = data.filter((element) => {
        if (warns.includes(element.name)) {
          numVulnerabilitiesWarns += element["vulnerability-matches"];
        } else {
          numVulnerabilitiesFails += element["vulnerability-matches"];
        }
        return element["vulnerability-matches"] > 0;
      }).map((element) => {
        return {
          name: element.name,
          warnOnly: warns.includes(element.name),
          version: element.version,
          path: registerModules[`${element.name}${element.version}`].path,
          vulnerabilities: element.vulnerabilities.map((element) => {
            return {
              title: element.title,
              description: element.description,
              versions: element.versions,
              references: element.references
            }
          })
        }
      });
      const vulnerabilityReport = {
        vulnerabilityFailCount: numVulnerabilitiesFails,
        vulnerabilityWarnCount: numVulnerabilitiesWarns,
        vulnerablePackages: vulnerablePackages
      };
      return callback(null, vulnerabilityReport);
    });
    request.on("error", callback);
  } else {
    return callback(null, {
      vulnerabilityCount: 0,
      vulnerablePackages: []
    });
  }
}
