import { IRapidScanResults } from '../blackduck-api'
import { createRapidScanReport, IComponentReport } from './report'
import { debug } from '@actions/core'

export const TABLE_HEADER = '| Policies Violated | Dependency | Transient Short Term Upgrade | Transient Long Term Upgrade | License(s) | Vulnerabilities | Direct Short Term Recommended Upgrade | Direct Long Term Recommended Upgrade |\r\n' + '|-|-|-|-|-|-|-|-|\r\n'

export async function createRapidScanReportString(policyViolations: IRapidScanResults[], policyCheckWillFail: boolean): Promise<string> {
  let message = ''
  if (policyViolations.length == 0) {
    message = message.concat('# :white_check_mark: None of your dependencies violate policy!')
  } else {
    const violationSymbol = policyCheckWillFail ? ':x:' : ':warning:'
    message = message.concat(`# ${violationSymbol} Found dependencies violating policy!\r\n\r\n`)

    const componentReports = await createRapidScanReport(policyViolations)
    const tableBody = componentReports.map(componentReport => createComponentRow(componentReport)).join('\r\n')
    const reportTable = TABLE_HEADER.concat(tableBody)
    message = message.concat(reportTable)
  }

  return message
}

function createComponentRow(component: IComponentReport): string {
  try {
    //Debug: Print out all parts of the component
    debug('Debugging component')
    debug(component.name)
    debug(
      component.violatedPolicies
        .map(function (elem) {
          return elem.policyName
        })
        .join('<br/>')
    )

    const violatedPolicies = component.violatedPolicies
      .map(function (elem) {
        return elem.policyName
      })
      .join('<br/>')
    //const depArray = component.dependencyTrees ? component.dependencyTrees.slice(1) : component.dependencyTrees
    const depTree = component.dependencyTrees ? component.dependencyTrees.join('<br/>&rarr;') : ''
    const componentInViolation = component?.href ? `[${component.name}](${component.href})` : component.name

    debug(component.licenses.map(license => license.name).join(','))
    const componentLicenses = component.licenses.map(license => `${license.violatesPolicy ? ':x: &nbsp; ' : ''}[${license.name}](${license.href})`).join('<br/>')
    const vulnerabilities = component.vulnerabilities.map(vulnerability => `${vulnerability.violatesPolicy ? ':x: &nbsp; ' : ''}[${vulnerability.name}](${vulnerability.href})${vulnerability.cvssScore && vulnerability.severity ? ` ${vulnerability.severity}: CVSS ${vulnerability.cvssScore}` : ''}`).join('<br/>')
    const depShortTerm = component.transitiveUpgradeGuidance ? component.transitiveUpgradeGuidance.map(transitive => transitive.shortTermUpgradeGuidance.externalId).join('<br/>') : ''
    const depLongTerm = component.transitiveUpgradeGuidance ? component.transitiveUpgradeGuidance.map(transitive => transitive.longTermUpgradeGuidance.externalId).join('<br/>') : ''
    const shortTerm = component.shortTermUpgradeGuidance ? `[${component.shortTermUpgradeGuidance.externalId}](${component.shortTermUpgradeGuidance.version})` : ''
    const longTerm = component.longTermUpgradeGuidance ? `[${component.longTermUpgradeGuidance.externalId}](${component.longTermUpgradeGuidance.version})` : ''

    //const shortTermString = component.shortTermUpgrade ? `[${component.shortTermUpgrade.name}](${component.shortTermUpgrade.href}) (${component.shortTermUpgrade.vulnerabilityCount} known vulnerabilities)` : ''
    //const longTermString = component.longTermUpgrade ? `[${component.longTermUpgrade.name}](${component.longTermUpgrade.href}) (${component.longTermUpgrade.vulnerabilityCount} known vulnerabilities)` : ''

    return `| ${violatedPolicies} |  ${componentInViolation}<br/>(${depTree}) | ${depShortTerm} | ${depLongTerm} | ${componentLicenses} | ${vulnerabilities} | ${shortTerm} | ${longTerm} |`
  } catch (e) {
    debug('Error creating component row')
    if (typeof e === 'string') {
      e.toUpperCase() // works, `e` narrowed to string
    } else if (e instanceof Error) {
      e.message // works, `e` narrowed to Error
      e.stack
    }
    return `|  |  |  |  | |  |`
  }
}
