const exec = require("executive");
const formatter = require("./formatters/default")
const Client = require("node-rest-client").Client;
const util = require("util");

module.exports.check = function(cwd, callback)
{
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
      let numVulnerabilities = 0;
      const vulnerablePackages = data.filter((element) => {
        numVulnerabilities += element["vulnerability-matches"];
        return element["vulnerability-matches"] > 0;
      }).map((element) => {
        return {
          name: element.name,
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
        vulnerabilityCount: numVulnerabilities,
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
