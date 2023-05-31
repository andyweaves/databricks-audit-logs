# databricks-audit-logs

[Delta Live Tables](https://databricks.com/product/delta-live-tables) makes it easy to build and manage reliable data pipelines that deliver high-quality data on Delta Lake.

This repo contains a DLT pipeline that can be used to process Databricks audit logs and prepare them for donwstream monitoring, analysis and alerting.

![image](https://user-images.githubusercontent.com/43955924/159453039-c8e5a653-c8dc-4353-84ce-3b22c984b2cf.png)

To get this DLT pipeline running on your environment, please use the following steps:

### Clone the repo and setup the DLT pipeline:

1. Clone this Github Repo using our Repos for Git Integration (see the docs for [AWS](https://docs.databricks.com/repos/index.html), [Azure](https://docs.microsoft.com/en-us/azure/databricks/repos/), [GCP](https://docs.gcp.databricks.com/repos/index.html)). 
2. Create a new DLT pipeline, linking to the [dlt_audit_logs.py](notebooks/dlt_audit_logs.py) notebook if you're writing to a Hive Metastore and [dlt_audit_logs_uc.py](notebooks/dlt_audit_logs_uc.py) notebook if you're writing to UC. See the docs for [AWS](https://docs.databricks.com/data-engineering/delta-live-tables/delta-live-tables-ui.html), [Azure](https://docs.microsoft.com/en-us/azure/databricks/data-engineering/delta-live-tables/delta-live-tables-ui), [GCP](https://docs.gcp.databricks.com/data-engineering/delta-live-tables/delta-live-tables-ui.html) for detailed steps.

### Hive Metastore Setup:

3. If you're writing to a Hive Metastore you’ll need to enter the following configuration options:

   * ```INPUT_PATH```: The cloud storage path that you’ve configured for audit log delivery. This will usually be a protected storage account which isn’t exposed to your Databricks users.
   * ```OUTPUT_PATH```: The cloud storage path you want to use for your audit log Delta Lakes. This will usually be a protected storage account which isn’t exposed to your Databricks users.
   * ```CONFIG_FILE```: The path to the [audit_logs.json](configuration/audit_logs.json) file once checked out in your repo. 
   
Note: once you’ve edited the settings that are configurable via the UI, you’ll need to edit the JSON so that you can add the configuration needed to authenticate with your ```INPUT_PATH``` and ```OUTPUT_PATH``` to the clusters object:

   * For AWS add the ```instance_profile_arn``` to the aws_attributes object.
   * For Azure add the Service Principal secrets to the ```spark_conf``` object.
   * For GCP add the ```google_service_account``` to the  ```gcp_attributes``` object.

### UC Setup:

3. If you're writing to a UC Metastore you’ll need to enter the following configuration options:
   * ```INPUT_PATH```: The cloud storage path that you’ve configured for audit log delivery. This will can either be a UC managed external location or a protected storage account which isn’t exposed to your Databricks users. If you choose to use a protected storage account, you will also need to add the appropriate cloud IAM configuration as per the note above.
   * ```CONFIG_FILE```: The path to the [audit_logs.json](configuration/audit_logs.json) file once checked out in your repo. 

4. Now you should be ready to configure your pipeline to run based on the appropriate schedule and trigger. Once it’s ran successfully, you should see something like this:

![image](https://user-images.githubusercontent.com/43955924/159453365-f8c0045d-45bb-46cf-a1ab-6b92ac640e3a.png)

There are a few things you should be aware of:

1. The pipeline processes data based on a configurable list of log levels and service names based on the [CONFIG_FILE](configuration/audit_logs.json) referenced above.
2. By default, the log levels are ```ACCOUNT_LEVEL``` and ```WORKSPACE_LEVEL```. Right now these are the only audit levels that we use at Databricks, but there’s no guarantee that we won’t add additional log levels in the future. It’s worth checking the audit log schema periodically to ensure that you aren’t missing any logs because new audit levels have been added (see the docs for [AWS](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html#audit-log-schema), [Azure](https://docs.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/azure-diagnostic-logs#diagnostic-log-schema), [GCP](https://docs.gcp.databricks.com/administration-guide/account-settings-gcp/audit-logs.html#schema-1)).
3. The serviceNames are more likely to change as we add new features and therefore services to the platform. They could also vary depending on whether customers leverage features like [PCI-DSS compliance controls](https://docs.databricks.com/administration-guide/cloud-configurations/aws/pci.html) or [Enhanced Security Mode](https://docs.databricks.com/administration-guide/cloud-configurations/aws/enhanced-security-mode.html). You can periodically check the list of service names on our public docs ([AWS](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html#audit-events), [Azure](https://docs.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/azure-diagnostic-logs#events), [GCP](https://docs.gcp.databricks.com/administration-guide/account-settings-gcp/audit-logs.html#audit-events)) but because the likelihood of this is greater, we’ve also added a detection mode into the DLT pipeline to make you aware if there are some new services that you’re not ingesting logs for. 

Once the pipeline has been run, you can use the [example sql queries](https://github.com/andyweaves/databricks-audit-logs/tree/main/sql) to query the curated data, and even better set up Databricks SQL alerts for actions that you want to be proactively informed of.
   * NB - for UC you may need to run ```USE CATALOG``` to select your target catalog first.