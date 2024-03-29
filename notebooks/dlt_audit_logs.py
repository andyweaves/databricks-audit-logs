# Databricks notebook source
INPUT_PATH = spark.conf.get("INPUT_PATH")
OUTPUT_PATH = spark.conf.get("OUTPUT_PATH")
CONFIG_FILE = spark.conf.get("CONFIG_FILE")

# COMMAND ----------

import json

def get_audit_levels_and_service_names(CONFIG_FILE):

  with open(CONFIG_FILE, 'r') as f:
    log_levels_and_service_names = json.load(f)["log_levels"]

  return log_levels_and_service_names

# COMMAND ----------

log_levels_and_service_names = get_audit_levels_and_service_names(CONFIG_FILE)

# COMMAND ----------

import dlt
from pyspark.sql.functions import input_file_name, col, from_utc_timestamp, from_unixtime

def create_bronze_tables(audit_level, service_names):
  
  @dlt.table(
    name=f"bronze_{audit_level}",
    path=f"{OUTPUT_PATH}bronze/{audit_level}/",
    partition_cols=["date"], 
    table_properties={
    "quality": "bronze", 
    "delta.autoOptimize.optimizeWrite": "true",
    "delta.autoOptimize.autoCompact": "true"
    }
  )
  @dlt.expect_all({"unexpected_service_names": f"serviceName IN {tuple(service_names)}"}) 
  def create_bronze_tables():
    return (spark.readStream
            .format("cloudFiles")
            .option("cloudFiles.format", "json") 
            .option("cloudFiles.includeExistingFiles", "true")
            .option("cloudFiles.inferColumnTypes", "true")
            .option("cloudFiles.schemaEvolutionMode", "rescue")
            .option("cloudFiles.schemaHints", "workspaceId long, requestParams map<string, string>, response struct<errorMessage: string, result: string, statusCode: bigint>")
            .option("cloudFiles.schemaLocation", f"{OUTPUT_PATH}bronze/schema/{audit_level}/")
            .load(INPUT_PATH)
            .where(f"auditLevel == '{audit_level.upper()}_LEVEL'")
            .withColumn("filename", input_file_name()))

# COMMAND ----------

def create_silver_tables(audit_level):
    
  @dlt.table(
    name=f"silver_{audit_level}",
    path=f"{OUTPUT_PATH}silver/{audit_level}/",
    partition_cols=["date"], 
    table_properties={
    "quality": "silver", 
    "delta.autoOptimize.optimizeWrite": "true",
    "delta.autoOptimize.autoCompact": "true",
    "pipelines.autoOptimize.zOrderCols": "serviceName,actionName,email"
    }
  )
  @dlt.expect_all({"valid_workspace_id": "workspaceId >=0", "timestamp_is_not_null": "timestamp IS NOT NULL", "service_name_is_not_null": "serviceName IS NOT NULL", "action_name_is_not_null": "actionName IS NOT NULL"})
  def create_silver_tables():
    return (dlt.read_stream(f"bronze_{audit_level}")
            .withColumn("timestamp", from_utc_timestamp(from_unixtime(col("timestamp") / 1000), "UTC"))
            .withColumn("email", col("userIdentity.email"))
            .withColumnRenamed("filename", "source_filename")
           .drop("_rescued_data", "userIdentity")
           )

# COMMAND ----------

def create_gold_tables(audit_level, service_name):
  
  @dlt.table(
      name=f"gold_{audit_level}_{service_name.replace('-', '_').lower()}",
      path=f"{OUTPUT_PATH}gold/{audit_level}/{service_name.replace('-', '_').lower()}/",
      partition_cols=["date"], 
      table_properties={
      "quality": "gold", 
      "delta.autoOptimize.optimizeWrite": "true",
      "delta.autoOptimize.autoCompact": "true",
      "pipelines.autoOptimize.zOrderCols": "actionName,email"
      }
    )

  @dlt.expect_all({"valid_service_name": f"serviceName = '{service_name}'"})
  def create_gold():
    return (dlt.read_stream(f"silver_{audit_level}")
           .where(f"serviceName == '{service_name}'")
           .selectExpr("*", "response.*")
           .drop("source_filename", "response"))

# COMMAND ----------

for log_level in log_levels_and_service_names:
  
  level = log_level["level"].split('_')[0].lower()
  service_names = log_level["service_names"].split(",")
  
  create_bronze_tables(level, service_names)
  create_silver_tables(level)
  
  for service in service_names:
  
    create_gold_tables(level, service)
