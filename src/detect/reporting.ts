import { IRapidScanResults } from '../blackduck-api'
import { createRapidScanReport, IComponentReport } from './report'
import { info, warning, setFailed, debug } from '@actions/core'

export const TABLE_HEADER = '| Policies Violated | Dependency | License(s) | Vulnerabilities | Short Term Recommended Upgrade | Long Term Recommended Upgrade |\r\n' + '|-|-|-|-|-|-|\r\n'

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

    const componentInViolation = component?.href ? `[${component.name}<br/>${component.externalId})](${component.href})` : component.name

    debug(component.licenses.map(license => license.name).join(','))
    const componentLicenses = component.licenses.map(license => `${license.violatesPolicy ? ':x: &nbsp; ' : ''}[${license.name}](${license.href})`).join('<br/>')
    debug(component.vulnerabilities.map(vulnerability => vulnerability.name).join(','))
    const vulnerabilities = component.vulnerabilities.map(vulnerability => `${vulnerability.violatesPolicy ? ':x: &nbsp; ' : ''}[${vulnerability.name}](${vulnerability.href})${vulnerability.cvssScore && vulnerability.severity ? ` ${vulnerability.severity}: CVSS ${vulnerability.cvssScore}` : ''}`).join('<br/>')
    const shortTermString = component.shortTermUpgrade ? `[${component.shortTermUpgrade.name}](${component.shortTermUpgrade.href}) (${component.shortTermUpgrade.vulnerabilityCount} known vulnerabilities)` : ''
    const longTermString = component.longTermUpgrade ? `[${component.longTermUpgrade.name}](${component.longTermUpgrade.href}) (${component.longTermUpgrade.vulnerabilityCount} known vulnerabilities)` : ''

    return `| ${violatedPolicies} | ${componentInViolation} | ${componentLicenses} | ${vulnerabilities} | ${shortTermString} | ${longTermString} |`
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
