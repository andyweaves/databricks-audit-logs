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
  window(timestamp, '30 minutes'),
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
ORDER BY window DESC
