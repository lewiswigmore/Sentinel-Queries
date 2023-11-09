# Sentinel vs Advanced Hunting: A Comprehensive Guide

## Overview

Microsoft Sentinel and Advanced Hunting are both integral parts of the Microsoft security ecosystem, providing advanced threat detection and response capabilities. They utilize Kusto Query Language (KQL) for querying and analyzing data, but they differ in schema and application. This guide aims to facilitate a smooth transition between the two by highlighting schema differences and providing query conversion techniques.

## Table of Contents

- [Introduction](#introduction)
- [Understanding the Schema Differences](#understanding-the-schema-differences)
- [Azure AD Signin Logs](#azure-ad-signin-logs)
  - [Interactive Signins](#interactive-signins)
  - [Non-Interactive Signins](#non-interactive-signins)
  - [Schema Conversion](#schema-conversion)
- [Azure AD Service Principal Signin Logs](#azure-ad-service-principal-signin-logs)
  - [Service Principal Signins](#service-principal-signins)
  - [Managed Identity Signins](#managed-identity-signins)
  - [Schema Differences](#schema-differences)
- [Conversion Examples](#conversion-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [FAQs](#faqs)
- [Additional Resources](#additional-resources)

## Introduction

Microsoft Sentinel is a scalable, cloud-native SIEM and SOAR platform that provides security insights across an enterprise, enabling rapid detection, investigation, and response to cyber threats. Advanced Hunting, embedded within Microsoft 365 Defender, is a query-based threat hunting tool that allows security analysts to explore raw data and identify breach indicators. Although both platforms utilize Kusto Query Language (KQL) for data exploration and threat detection, they differ in their data schema and operational context. This guide delineates these differences and furnishes conversion techniques to help practitioners adapt queries across both environments effectively, ensuring a cohesive and efficient security monitoring and response strategy.

## Understanding the Schema Differences

The schema differences between Microsoft Sentinel and Advanced Hunting are mainly evident in naming conventions, table structures, and the contextual metadata attached to various security logs. These discrepancies must be understood for effective query translation and analysis:

- **Time fields**: `TimeGenerated` in Sentinel corresponds to `Timestamp` in Advanced Hunting. This is critical for time-based queries and tracking the occurrence of events.
- **User identifiers**: `UserPrincipalName` in Sentinel is equivalent to `AccountUpn` in Advanced Hunting. Both serve as primary identifiers for user accounts but under different attribute names.
- **Account display names**: `UserDisplayName` in Sentinel maps to `AccountDisplayName` in Advanced Hunting, representing the full name of the user associated with the event.
- **Object IDs**: `UserId` in Sentinel should be referenced as `AccountObjectId` in Advanced Hunting, which uniquely identifies user accounts in Azure AD.
- **Application identifiers**: `AppDisplayName` and `AppId` in Sentinel correspond to `Application` and `ApplicationId` in Advanced Hunting, respectively, and are used to identify the application involved in the event.
- **Authentication details**: Fields describing authentication events, such as `ResultType` in Sentinel, are typically matched to `ErrorCode` or similar fields in Advanced Hunting, outlining the outcome of the authentication attempt.
- **Device information**: In Sentinel, device details like `DeviceId` and `DeviceName` are often nested within JSON objects and must be extracted, whereas in Advanced Hunting, these are usually top-level attributes.

The rationale for these differences often stems from the distinct design goals of each platform. Sentinel, being a broad SIEM platform, structures its schema for generalization across diverse data sources, while Advanced Hunting is tailored for in-depth threat hunting within the Microsoft 365 ecosystem, resulting in a schema optimized for that context. Understanding these nuances is essential for analysts to accurately map and execute queries when transitioning between Sentinel and Advanced Hunting.

## Azure AD Signin Logs

### Interactive Signins

In Sentinel, interactive sign-ins are tracked separately, facilitating targeted analysis and alerting. Query example:

```kql
// Sentinel
SigninLogs
| take 10
```

For Advanced Hunting, interactive and non-interactive sign-ins are consolidated, with distinctions made using the `LogonType` field:

```kql
// Advanced Hunting
AADSignInEventsBeta
| where LogonType == @"[""interactiveUser""]"
| take 10
```

### Non-Interactive Signins

Similarly, non-interactive sign-ins in Sentinel are segregated for precise monitoring:

```kql
// Sentinel
AADNonInteractiveUserSignInLogs
| take 10
```

Advanced Hunting uses the same table as interactive sign-ins, differentiated by `LogonType`:

```kql
// Advanced Hunting
AADSignInEventsBeta
| where LogonType == @"[""nonInteractiveUser""]"
| take 10
```

### Schema Conversion

The following table illustrates the schema differences and how to convert queries between Sentinel and Advanced Hunting:

| Sentinel Field       | Advanced Hunting Field    | Description                                                                                           |
|------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------|
| `TimeGenerated`              | `Timestamp`               | Used to specify the date and time when the event was generated.                                       |
| `UserPrincipalName`          | `AccountUpn`              | The username or principal name associated with the event.                                             |
| `UserDisplayName`            | `AccountDisplayName`      | The full display name of the user associated with the event.                                          |
| `UserId`                     | `AccountObjectId`         | A unique identifier for the user in Azure AD.                                                         |
| `AppDisplayName`             | `Application`             | The name of the application involved in the event.                                                    |
| `AppId`                      | `ApplicationId`           | A unique identifier for the application involved in the event.                                        |
| `DeviceDetail.deviceId`      | `DeviceId`                | The unique identifier of the device involved in the event.                                            |
| `DeviceDetail.displayName`   | `DeviceName`              | The display name of the device involved in the event.                                                 |
| `ResultType`                 | `ErrorCode`               | The result or error code associated with an authentication attempt or other security event.           |
| `DeviceDetail.trustType`     | `DeviceTrustType`         | Indicates the trust type of the device (e.g., 'Azure AD registered').                                 |
| `DeviceDetail.operatingSystem` | `OSPlatform`           | The operating system of the device involved in the event.                                             |
| `LocationDetails.city`       | `City`                    | The city derived from the IP address associated with the event.                                       |
| `LocationDetails.countryOrRegion` | `Country`            | The country or region derived from the IP address associated with the event.                          |
| `LocationDetails.geoCoordinates.latitude` | `Latitude`  | The latitude component of the geolocation associated with the event.                                  |
| `LocationDetails.geoCoordinates.longitude` | `Longitude` | The longitude component of the geolocation associated with the event.                                |

## Azure AD Service Principal Signin Logs

Service Principal sign-in logs are critical for security monitoring in Azure, as they track authentications by non-human accounts such as applications or services. Microsoft Sentinel stores these logs in specific tables, while Advanced Hunting uses a unified table approach. The distinction helps Sentinel offer detailed analytics, whereas Advanced Hunting simplifies threat hunting by consolidating data. Understanding the storage and categorization differences between platforms is crucial for effective security incident investigation and response.

### Service Principal Signins

Sentinel captures regular service principal sign-ins in a dedicated table:

```kql
// Sentinel
AADServicePrincipalSignInLogs
| take 10
```

In Advanced Hunting, the distinction is made through a field within a unified table:

```kql
// Advanced Hunting
AADSpnSignInEventsBeta
| where IsManagedIdentity == 0
```

### Managed Identity Signins

For managed identities, Sentinel uses:

```kql
// Sentinel
AADManagedIdentitySignInLogs
| take 10
```

Advanced Hunting employs a similar approach as with service principal sign-ins:

```kql
// Advanced Hunting
AADSpnSignInEventsBeta
| where IsManagedIdentity == 1
```

### Schema Differences

The schema for Service Principal sign-in logs between Microsoft Sentinel and Advanced Hunting varies, as outlined in the table below. These differences reflect the unique design decisions of each platform to cater to their specific security monitoring objectives.

| Sentinel Field                   | Advanced Hunting Field    | Description                                                                                            |
|----------------------------------|---------------------------|--------------------------------------------------------------------------------------------------------|
| `TimeGenerated`                  | `Timestamp`               | The timestamp indicating when the sign-in event was generated.                                         |
| `AppDisplayName`                 | `Application`             | The display name of the application for which the service principal is authenticating.                 |
| `AppId`                          | `ApplicationId`           | The unique identifier for the application associated with the service principal.                        |
| `AADServicePrincipalSignInLogs`  | `AADSpnSignInEventsBeta`  | Sentinel separates regular and managed identity sign-ins into different tables, whereas Advanced Hunting uses a single table with a field to distinguish the two. |
| `AADManagedIdentitySignInLogs`   | `AADSpnSignInEventsBeta`  | For managed identities, Sentinel uses a separate table, but Advanced Hunting uses a boolean field within a single table. |
| `ResultType`                     | `ErrorCode`               | The result code associated with the service principal's sign-in attempt.                                |
| `LocationDetails.city`           | `City`                    | The city derived from the IP address associated with the sign-in event.                                 |
| `LocationDetails.countryOrRegion`| `Country`                 | The country or region derived from the IP address of the sign-in event.                                 |
| `LocationDetails.geoCoordinates.latitude` | `Latitude`      | The latitude extracted from the geolocation details of the sign-in event.                               |
| `LocationDetails.geoCoordinates.longitude` | `Longitude`   | The longitude extracted from the geolocation details of the sign-in event.                              |
| `UserId`                         | `AccountObjectId`         | In Sentinel, `UserId` often refers to the service principal's ID, while Advanced Hunting uses `AccountObjectId`. |

## Best Practices

When working with Microsoft Sentinel and Advanced Hunting, consider the following best practices to ensure efficient and accurate query translation and execution:

- **Verify Schema Mappings**: Always double-check the schema mappings when converting queries. An incorrect field name or datatype can result in errors or inaccurate data retrieval.
- **Test Incrementally**: When building complex queries, test them incrementally to ensure each part of the query works as expected before combining them.
- **Optimize Performance**: Be mindful of query performance. Use filters to narrow down the data set and avoid unnecessarily large data scans.
- **Use Available Functions**: Leverage KQL functions to transform and manage data. This can include type conversion, string manipulation, and date-time calculations.
- **Stay Updated**: Both Sentinel and Advanced Hunting are regularly updated. Stay informed about the latest changes in schema and functionality.
- **Secure Access**: Ensure that only authorized personnel have access to modify analytic rules and queries to maintain the integrity and security of your environment.

## Common Troubleshooting

If you encounter issues while working with Sentinel and Advanced Hunting, consider the following tips:

- **Query Syntax Errors**: Review the KQL syntax for any typos or syntax errors. Use the KQL documentation as a reference.
- **Field Mismatches**: Confirm that the field names and types match the schema of the logs you're querying. Schema changes can occur, so it’s important to verify.
- **Time Zone Differences**: TimeGenerated and Timestamp fields are in UTC. If you’re filtering by time, ensure you account for any time zone differences.
- **Data Volume**: Large data volumes can slow down or timeout queries. Use filters to narrow down the results or consider increasing resources.
- **Permissions**: Lack of access or incorrect permissions can prevent queries from executing. Verify that your account has the necessary permissions.

## FAQs

**Q: Can I use Sentinel queries directly in Advanced Hunting without modification?**
A: No, due to schema differences, you'll need to adjust field names and sometimes query structure to fit the schema of Advanced Hunting.

**Q: How can I keep up with changes to Sentinel and Advanced Hunting schemas?**
A: Regularly check the official Microsoft documentation and subscribe to update notifications in the Azure portal.

**Q: Are there limits to the amount of data I can query with KQL?**
A: Yes, both Sentinel and Advanced Hunting have data limits and performance considerations. It's best to optimize queries for the necessary data to avoid performance degradation.

**Q: What should I do if a query works in Sentinel but not in Advanced Hunting?**
A: Verify that all field names and data types are correctly mapped to the Advanced Hunting schema. Also, check for any product-specific functionalities or operators that may not be available across both platforms.

## Additional Resources

- **KQL Documentation**: [Azure Data Explorer KQL documentation](https://docs.microsoft.com/azure/data-explorer/kusto/query/)
- **Microsoft Sentinel Documentation**: [Microsoft Sentinel official documentation](https://docs.microsoft.com/azure/sentinel/)
- **Advanced Hunting Documentation**: [Advanced Hunting in Microsoft 365 Defender](https://docs.microsoft.com/microsoft-365/security/defender/advanced-hunting-overview)
- **Community Forums**: Engage with the [Microsoft Tech Community](https://techcommunity.microsoft.com/) for Sentinel and [Microsoft Security Community](https://securitycommunity.microsoft.com/) for Advanced Hunting.
- **Online Courses**: Consider taking online courses on platforms like Coursera, Udemy, or LinkedIn Learning for in-depth KQL and Azure security analytics training.
