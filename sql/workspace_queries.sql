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
-- MAGIC ### Failed Login Attempts over Time
-- MAGIC The query below extends the horizon of looking at events over 30 minute windows, and looks for trends relating to failed login attempts over the period of 6 months

-- COMMAND ----------

SELECT
  date_trunc("week", date) AS week,
  requestParams.user,
  count(*) AS total
FROM
  audit_logs.gold_workspace_accounts
WHERE
  actionName IN ('login', 'tokenLogin')
  AND statusCode IN (401, 403)
  AND date >= current_date - 180
GROUP BY
  1,
  2
ORDER BY week DESC, total DESC

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

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### How reliable are my jobs?
-- MAGIC The following query will show you the job run succeeded v failure rate across all workspaces, so you can see at an enterprise level how reliable your jobs are

-- COMMAND ----------

SELECT
  date,
  actionName,
  count(*) AS total
FROM
  audit_logs.gold_workspace_jobs
WHERE actionName IN ("runSucceeded", "runFailed")
GROUP BY 1, 2
ORDER BY date DESC, total DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Which IP Addresses are being used to connect to my workspaces?
-- MAGIC The following query will show you which IP addresses have been used to connect to your workspaces over the last 90 days. Note that as well as your end users, the clusters themselves and some internal Databricks services may also interact with your workspace so you may see some IP addresses outside of your corporate range in this list. As long as the vast majority of connections are ones that you expect to see, and there aren't any that appear to abnormal, everything is probably working normally

-- COMMAND ----------

SELECT
  sourceIpAddress AS source_ip,
  response.statusCode,
  count(*) AS num_requests
FROM
  audit_logs.silver_workspace
WHERE
  date >= current_date - 90
  AND sourceIpAddress != ""
  AND response.statusCode IS NOT NULL
  AND response.statusCode BETWEEN 200
  AND 599
GROUP BY
  1,
  2
ORDER BY
  num_requests DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Verbose Audit Logs
-- MAGIC When enabled, [verbose audit logs](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html#configure-verbose-audit-logs) capture the notebook and SQL commands run interactively by your users. The following queries show how you can analyze these in a number of different scenarios.

-- COMMAND ----------

-- MAGIC %md
-- MAGIC Use of the ```display()``` function within the last day

-- COMMAND ----------

SELECT
  date,
  sourceIPAddress,
  email,
  requestParams.commandText,
  COUNT(*) AS total
FROM
  audit_logs.gold_workspace_notebook
WHERE
  actionName = "runCommand"
  AND timestamp >= current_date() - 1
  AND requestParams.commandText rlike ".*display(.*).*"
GROUP BY 1, 2, 3, 4
ORDER BY total DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC Use of the print() function within the last day

-- COMMAND ----------

SELECT
  date,
  sourceIPAddress,
  email,
  requestParams.commandText,
  COUNT(*) AS total
FROM
  audit_logs.gold_workspace_notebook
WHERE
  actionName = "runCommand"
  AND timestamp >= current_date() - 1
  AND requestParams.commandText rlike 'print[/s]?(?! e)(.)+'
GROUP BY 1, 2, 3, 4
ORDER BY total DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC Use of a specific ```query_string``` within the last day - can be used in scenarios like 0 day exploits to find use of specific libraries (I.e. searching for ```import ctx```) 
-- MAGIC 
-- MAGIC  NB ```{{query_string}}``` denotes a DB SQL widget, and so this query should be used in Databricks SQL or modified to use notebook widgets like ```getArgument()``` instead

-- COMMAND ----------

SELECT
  timestamp,  
  workspaceId,
  sourceIPAddress,
  email,
  requestParams.commandText,
  requestParams.status,
  requestParams.executionTime,
  requestParams.notebookId,
  result,
  errorMessage
FROM
  audit_logs.gold_workspace_notebook
 WHERE actionName = "runCommand"
 AND timestamp >= current_date() - 1
 AND contains(requestParams.commandText, {{query_string}})
 ORDER BY timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC All SQL ```SELECT``` or CRUD statements run interactively from a notebook and all Databricks SQL queries run interactively over the last day

-- COMMAND ----------

SELECT
  timestamp,
  sourceIPAddress,
  email,
  requestParams.commandText,
  actionName,
  requestId,
  userAgent,
  statusCode
FROM
  audit_logs.gold_workspace_notebook
WHERE
  actionName = "runCommand"
  AND timestamp >= current_date() - 1
  AND startswith(requestParams.commandText, 'SELECT')
  OR startswith(requestParams.commandText, 'CREATE')
  OR startswith(requestParams.commandText, 'DROP')
  OR startswith(requestParams.commandText, 'ALTER')
  OR startswith(requestParams.commandText, 'DELETE')
UNION ALL
SELECT
  timestamp,
  sourceIPAddress,
  email,
  requestParams.commandText,
  actionName,
  requestId,
  userAgent,
  statusCode
FROM
  audit_logs.gold_workspace_databrickssql
WHERE
  actionName IN ("commandSubmit", "commandFinish")
  AND timestamp >= current_date() - 1
ORDER BY
  timestamp DESC
