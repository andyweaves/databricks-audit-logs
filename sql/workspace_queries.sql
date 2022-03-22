-- Databricks notebook source
-- MAGIC %md
-- MAGIC ### Databricks Access via Genie
-- MAGIC This is to detect logins to your workspace via Databricks support process, called Genie. This access is tied to a support or engineering ticket while also complying with your [workspace configuration](https://docs.databricks.com/administration-guide/genie.html) that may disable such access on AWS or Azure.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_genie
WHERE
  actionName = 'databricksAccess'
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Repeated Failed Login Attempts For Local Accounts
-- MAGIC Customers are encouraged to leverage their SSO capability and disable local password usage entirely. In the event local passwords are still used, this detection helps monitor for any possible brute force attacks to login to the workspace. In the example below, it buckets repeated login attempts in a 30 minute window.

-- COMMAND ----------

SELECT
  WINDOW(timestamp, '30 minutes'),
  requestParams.user,
  statusCode,
  count(*) AS total
FROM
  audit_logs.gold_workspace_accounts
WHERE
  actionName IN ('login', 'tokenLogin')
  AND statusCode <> 200
GROUP BY
  1,
  2,
  3
ORDER BY WINDOW DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###IP Access List Failures
-- MAGIC Databricks allows customers to configure [IP Access Lists](https://docs.databricks.com/security/network/ip-access-list.html) to restrict access to their workspaces. However, they may want monitor and be alerted whenever access is attempted from an untrusted network. The following query can be used to monitor all ```IpAccessDenied``` events.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_accounts
WHERE
  actionName = "IpAccessDenied"
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Admin Permission Changes
-- MAGIC Databricks admin users should be limited to few trusted personas responsible for managing the deployment. The granting of new admin privileges should be reviewed.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_accounts
WHERE
  actionName IN ('setAdmin', 'removeAdmin')
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###Changes To Workspace Permissions
-- MAGIC Not all workspace permission changes may be suspicious, but there may be some specific situations that should be monitored. For example, if you’re relying on cluster isolation where different user groups have access to specific clusters then any changes to cluster permissions could be a sign of unauthorized access.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_clusters
WHERE
  actionName IN ("changeClusterAcl", "changeClusterPolicyAcl")
ORDER BY
  timestamp DESC

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_databrickssql
WHERE
  actionName IN ("changeEndpointAcls", "changePermissions")
ORDER BY
  timestamp DESC

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_iamrole
WHERE
  actionName IN ("changeIamRoleAcl", "changeIamRoleAssumeAcl")
ORDER BY
  timestamp DESC

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_jobs
WHERE
  actionName IN ("changeJobAcl", "resetJobAcl")
ORDER BY
  timestamp DESC

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_secrets
WHERE
  actionName IN ("putAcl", "deleteAcl")
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###Personal Access Token Activity
-- MAGIC You may want to monitor activity related to personal access tokens, such as logins and new tokens being generated.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  requestParams.user,
  requestParams.tokenId,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_accounts
WHERE
  actionName IN ('tokenLogin', 'generateDbToken')
ORDER BY timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###Changes To Workspace Configurations
-- MAGIC Admins should monitor any changes to workspace configurations, such as storage location of query results, SSO, etc.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  requestParams.workspaceConfKeys,
  requestParams.workspaceConfValues,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_workspace
WHERE
  actionName = 'workspaceConfEdit'
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Use of DBFS
-- MAGIC Because you cannot set ACLs within a workspace on DBFS locations, Databricks recommends that you do not use the Databricks File System to store your data. The following query shows users who are performing Create or Update actions within the ```dbfs:/``` file system.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_dbfs
WHERE
  actionName IN ("create", "mkdirs", "move", "put")
  AND startswith(requestParams.path, "dbfs:/")
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Use of Mount Points
-- MAGIC Mount points can be an anti-pattern because on all 3 clouds there is the possibility of mounting external storage with cached credentials. These mount points will be accessible by all users of a workspace, bypassing any user level access controls. The following query can be used to monitor mount point creation, such that administrators can be alerted to the creation of mount points to external storages that are not expected. 

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_dbfs
WHERE
  actionName = "mount"
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###Download Results
-- MAGIC Databricks allows customers to configure whether they want users to be able to download [notebook](https://docs.databricks.com/administration-guide/workspace/notebooks.html#manage-download-results) or [SQL query](https://docs.databricks.com/sql/admin/general.html) results, but some customers might want to monitor and report rather than prevent entirely. The following query can be used to monitor the download of results from notebooks, Databricks SQL, as well as the exporting of notebooks in formats that may contain query results.

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  email,
  serviceName,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_notebook
WHERE
  actionName IN ("downloadPreviewResults", "downloadLargeResults")
UNION ALL
SELECT 
  timestamp,
  workspaceId,
  email,
  serviceName,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_databrickssql WHERE actionName IN ("downloadQueryResult")
UNION ALL 
SELECT
  timestamp,
  workspaceId,
  email,
  serviceName,
  actionName,
  requestParams,
  sourceIPAddress
FROM
  audit_logs.gold_workspace_workspace
WHERE
  actionName IN ("workspaceExport")
  AND requestParams.workspaceExportFormat !="SOURCE"
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###ClamAV Scan Results
-- MAGIC Customers who have a requirement to process cardholder data as defined by PCI-DSS, or who have elevated security requirements can choose to leverage our [PCI-DSS compliance controls](https://docs.databricks.com/administration-guide/cloud-configurations/aws/pci.html) or [Enhanced Security Mode](https://docs.databricks.com/administration-guide/cloud-configurations/aws/enhanced-security-mode.html) features on AWS. 
-- MAGIC 
-- MAGIC The query below searches [audit log entries related to ClamAV](https://docs.databricks.com/administration-guide/cloud-configurations/aws/monitor-log-schemas.html#clamav-audit-log-row-schema) to find any occurances where the AV scan has detected infected files

-- COMMAND ----------

SELECT
  timestamp,
  workspaceId,
  actionName,
  requestParams.instanceId,
  result
FROM
  audit_logs.gold_workspace_clamavscanservice_dataplane
WHERE
  startswith(result, "Infected files:")
  AND regexp_extract(result, ("Infected files: (\\d+)")) >= 1
ORDER BY
  timestamp DESC
