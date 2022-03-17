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
  window(timestamp, '30 minutes'),
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
ORDER BY window DESC

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
  actionName = 'changeClusterAcl'
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
  actionName IN ('changeEndpointAcls', 'changePermissions')
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
  actionName = 'changeIamRoleAcl'
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
  actionName IN ('changeJobAcl', 'resetJobAcl')
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
