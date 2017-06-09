const Table = require("cli-table");
const chalk = require("chalk");

function format(vulnerabilityReport)
{
  let returnString = "";

  if (vulnerabilityReport.vulnerabilityCount === 0) {
    return chalk.green("(+)") + " No known vulnerabilities found.";
  } else {
    returnString = chalk.yellow(`(+) ${vulnerabilityReport.vulnerabilityCount} vulnaribilities found.\n`);
  }

  let width = 80;
  let colWidth = 15;
  if (process.stdout.isTTY) {
    width = process.stdout.getWindowSize()[0] - 10;
    if (!width || width <= colWidth) {
      width = 80;
    }
  }

  vulnerabilityReport.vulnerablePackages.forEach((vulnerablePackage) => {
    const table = new Table({
      head: [ "", `${vulnerablePackage.name}@${vulnerablePackage.version}` ],
      colWidths: [ colWidth, width - colWidth ]
    });
    table.push(["Path", vulnerablePackage.path.join(" > ")]);
    vulnerablePackage.vulnerabilities.forEach((vulnerability) => {
      table.push([chalk.bold("Vulnerability"), chalk.bold(vulnerability.title)]);
      table.push(["Description", vulnerability.description]);
      table.push(["Affected Versions", vulnerability.versions]);
      table.push(["References", vulnerability.references.join("\n")]);
      table.push([]);
    });
    returnString += table.toString() + "\n";
  });
  return returnString;
}

module.exports = {
  format: format,
  description: "Outputs the vulnerabilities in a table-like format.",
  key: "default"
}
