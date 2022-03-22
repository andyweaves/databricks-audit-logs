# databricks-audit-logs

[Delta Live Tables](https://databricks.com/product/delta-live-tables) makes it easy to build and manage reliable data pipelines that deliver high-quality data on Delta Lake.

This repo contains a DLT project 

![image](https://user-images.githubusercontent.com/43955924/159453039-c8e5a653-c8dc-4353-84ce-3b22c984b2cf.png)

To get the new DLT pipeline running on your environment, please use the following steps:

1. Clone the Github Repo using the repos for Git Integration (see the docs for AWS, Azure, GCP). 
2. Create a new DLT pipeline, linking to the dlt_audit_logs.py notebook (see the docs for AWS, Azure, GCP). You’ll need to enter the following configuration options:
a) ```INPUT_PATH```: The cloud storage path that you’ve configured for audit log delivery. This will usually be a protected storage account which isn’t exposed to your Databricks users.
b) ```OUTPUT_PATH```: The cloud storage path you want to use for your audit log Delta Lakes. This will usually be a protected storage account which isn’t exposed to your Databricks users.
c) ```CONFIG_FILE```: The path to the audit_logs.json file once checked out in your repo. 
3. Note: once you’ve edited the settings that are configurable via the UI, you’ll need to edit the JSON so that you can add the configuration needed to authenticate with your INPUT_PATH and OUTPUT_PATH to the clusters object:
a) For AWS add the instance_profile_arn to the aws_attributes object.
b) For Azure add the Service Principal secrets to the spark_conf object.
c) For GCP add the google_service_account to the  gcp_attributes object.
4. Now you should be ready to configure your pipeline to run based on the appropriate schedule and trigger. Once it’s ran successfully, you should see something like this:

![image](https://user-images.githubusercontent.com/43955924/159453365-f8c0045d-45bb-46cf-a1ab-6b92ac640e3a.png)

There are a few things you should be aware of:

1. The pipeline processes data based on a configurable list of log levels and service names based on the CONFIG_FILE referenced above.
2. By default, the log levels are ACCOUNT_LEVEL and WORKSPACE_LEVEL. Right now these are the only audit levels that we use at Databricks, but there’s no guarantee that we won’t add additional log levels in the future. It’s worth checking the audit log schema periodically to ensure that you aren’t missing any logs because new audit levels have been added (see the docs for AWS, Azure, GCP).
3. The serviceNames are more likely to change as we add new features and therefore services to the platform. They could also vary depending on whether customers leverage features like PCI-DSS compliance controls or Enhanced Security Mode. You can periodically check the list of service names on our public docs (AWS, Azure, GCP) but because the likelihood of this is greater, we’ve also added a detection mode into the DLT pipeline to make you aware if there are some new services that you’re not ingesting logs for. Read on for more information about how we use expectations in Delta Live Tables to detect potential data quality issues like this. 
