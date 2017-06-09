const Table = require("cli-table");
const chalk = require("chalk");

const DEFAULT_SCREEN_WIDTH = 80;
const FIRST_COLUMN_WIDTH = 15;
const TTY_MARGIN = 10;  //< Margin to leave for the TTY prompt

/**
 * Returns a pretty-formatted output generated from the given vulnerability report
 * @param  {!VulnerabilityReport} vulnerabilityReport - the vulnerability report to format
 * @return {!String} printable string representation of the report
 * @private
 */
function format(vulnerabilityReport) {
  let returnString = "";

  if (vulnerabilityReport.vulnerabilityCount === 0) {  //eslint-disable-line no-magic-numbers
    return `${chalk.green("(+)")} No known vulnerabilities found.`;
  } else {
    returnString = chalk.yellow(`(+) ${vulnerabilityReport.vulnerabilityCount} vulnaribilities found.\n`);
  }

  let width = DEFAULT_SCREEN_WIDTH;
  const firstColumnWidth = FIRST_COLUMN_WIDTH;

  if (process.stdout.isTTY) {
    width = process.stdout.getWindowSize()[0] - TTY_MARGIN;
    if (!width || width <= firstColumnWidth) {
      width = DEFAULT_SCREEN_WIDTH;
    }
  }

  vulnerabilityReport.vulnerablePackages.forEach((vulnerablePackage) => {
    const table = new Table({
      head:      ["", `${vulnerablePackage.name}@${vulnerablePackage.version}`],
      colWidths: [firstColumnWidth, width - firstColumnWidth]
    });

    table.push(["Path", vulnerablePackage.path.join(" > ")]);
    vulnerablePackage.vulnerabilities.forEach((vulnerability) => {
      table.push([chalk.bold("Vulnerability"), chalk.bold(vulnerability.title)]);
      table.push(["Description", vulnerability.description]);
      table.push(["Affected Versions", vulnerability.versions]);
      table.push(["References", vulnerability.references.join("\n")]);
      table.push([]);
    });
    returnString += `${table.toString()}\n`;
  });

  return returnString;
}

module.exports = {
  format:      format,
  description: "Outputs the vulnerabilities in a table-like format.",
  key:         "default"
};
