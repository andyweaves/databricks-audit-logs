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

def create_bronze_tables(audit_level):
  
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
  @dlt.expect("clean_schema", "_rescued_data IS NULL")
  def create_bronze_tables():
    return (spark.readStream
            .format("cloudFiles")
            .option("cloudFiles.format", "json") 
            .option("cloudFiles.includeExistingFiles", "true")
            .option("cloudFiles.inferColumnTypes", "true")
            .option("cloudFiles.schemaEvolutionMode", "addNewColumns")
            .option("cloudFiles.schemaHints", "requestParams map<string, string>")
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
  @dlt.expect_all({"timestamp_is_not_null": "timestamp IS NOT NULL"})
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
      name=f"gold_{audit_level}_{service_name.lower()}",
      path=f"{OUTPUT_PATH}gold/{audit_level}/{service_name.lower()}/",
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
           .drop("filename"))

# COMMAND ----------

for log_level in log_levels_and_service_names:
  
  log_level_name = log_level["level"].split('_')[0].lower()
  
  create_bronze_tables(log_level_name)
  create_silver_tables(log_level_name)
  
  for service in log_level["service_names"].split(","):
  
    create_gold_tables(log_level_name, service)
