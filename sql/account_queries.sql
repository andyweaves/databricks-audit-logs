-- Databricks notebook source
-- MAGIC %md
-- MAGIC ### Account Admin Permission Changes
-- MAGIC Databricks account admin users should be limited to few trusted personas responsible for managing your Databricks account. The granting of new admin privileges should be reviewed.

-- COMMAND ----------

SELECT
  timestamp,
  email,
  actionName,
  requestParams.targetUserName,
  sourceIpAddress
FROM
  audit_logs.gold_account_accounts
WHERE
  actionName IN ("setAccountAdmin", "removeAccountAdmin")
ORDER BY
  timestamp DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Repeated Failed Login Attempts
-- MAGIC Customers are encouraged to leverage their SSO capability and disable local password usage for all users except the account owner. In the event local passwords are still used, this detection helps monitor for any possible brute force attacks to login to the workspace. In the example below, it buckets repeated login attempts in a 30 minute window.

-- COMMAND ----------

SELECT
  WINDOW(timestamp, '30 minutes'),
  requestParams.user,
  statusCode,
  count(*) AS total
FROM
  audit_logs.gold_account_accounts
WHERE
  actionName = 'login'
  AND statusCode <> 200
GROUP BY
  1,
  2,
  3
ORDER BY WINDOW DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ###Detect changes to Production workspaces
-- MAGIC Databricks account administrators can [Create and manage workspaces using the account console](https://docs.databricks.com/administration-guide/account-settings-e2/workspaces.html). However, for specific resources (I.e. production workspaces) you may want to be proactively informed if they have been updated or deleted. 
-- MAGIC 
-- MAGIC The following query can be used to monitor changes to Databricks workspaces which have ```prod``` in their ```workspace_name```

-- COMMAND ----------

SELECT
  timestamp,
  email,
  actionName,
  requestParams.workspace_id AS workspace_id,
  requestParams,
  result:workspace.workspace_name AS workspace_name,
  result:workspace.aws_account_id AS aws_account_id
FROM
  audit_logs.gold_account_accountsmanager
WHERE
  actionName IN (
    "updateWorkspaceConfiguration",
    "deleteWorkspaceConfiguration"
  )
  AND contains(result:workspace.workspace_name, "prod")
ORDER BY
  timestamp DESC
