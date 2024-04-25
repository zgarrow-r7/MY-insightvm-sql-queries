select
dim_asset.host_name as "Asset Name",
dim_asset.ip_address as "Asset IP Address",
dim_asset.os_description as "Asset OS",
dim_vulnerability.vulnerability_id as "Vulnerability Identifier",
dim_vulnerability.title as "Vulnerability Title",
dim_vulnerability.cvss_score as "Vulnerability CVSS Score",
dim_vulnerability.exploits as "Exploits Available",
dim_vulnerability.exploit_skill_level as "Exploit Minimum Skill",
dim_vulnerability.description as "Vulnerability Description",
dim_vulnerability.date_published as "Vulnerability Published Date",
fact_asset_vulnerability_remediation_date."day" as "Vulnerability Remediation Date"
from
    dim_asset_group_asset
        inner join
    fact_asset_vulnerability_remediation_date
        on dim_asset_group_asset.asset_id = fact_asset_vulnerability_remediation_date.asset_id
        inner join 
    dim_asset
    	on fact_asset_vulnerability_remediation_date.asset_id = dim_asset.asset_id
    	inner join
    dim_vulnerability
        on fact_asset_vulnerability_remediation_date.vulnerability_id = dim_vulnerability.vulnerability_id;
--where
--CAST(fact_asset_vulnerability_remediation_date."day" as text) ilike '%2020-03%';
