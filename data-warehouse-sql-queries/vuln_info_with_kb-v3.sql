SELECT
   DISTINCT ON (dv.vulnerability_id, da.ip_address, da.host_name) da.ip_address AS "IP Address",
   da.host_name AS "Hostname",  
   dos.name AS "Operating System Name",
   dos.version AS "Operating System Version",
   round(fava.age_in_days :: numeric, 0) AS "Days on Asset",
   dt.tag_name AS "Tags Applied",
   dv.riskscore AS "Vulnerability Riskscore",
   substring(dv.title from 'CVE-[0-9]+-[0-9]+') AS "Vulnerability CVE ID",
   dv.title AS "Vulnerability Name",
   dv.severity AS "Vulnerability Severity Level",
   dv.description AS "Vulnerability Description",
   proofAsText(ds.fix) AS "Solution",
   substring(ds.summary from 'KB[0-9]+') AS "KB Article",
   proofAsText(ds.fix) AS "Proof",
   dvr.reference AS "External References"
FROM
   dim_asset da
   JOIN dim_tag_asset dta on dta.asset_id = da.asset_id
   JOIN dim_tag dt on dt.tag_id = dta.tag_id
   JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
   JOIN dim_asset_vulnerability_best_solution davbs ON davbs.asset_id = da.asset_id
   JOIN dim_solution ds ON ds.solution_id = davbs.solution_id
   JOIN dim_vulnerability dv ON dv.vulnerability_id = davbs.vulnerability_id
   JOIN dim_vulnerability_reference dvr ON dv.vulnerability_id = dvr.vulnerability_id
   JOIN fact_asset_vulnerability_age fava ON dv.vulnerability_id = fava.vulnerability_id
   JOIN fact_asset_vulnerability_finding fasvf ON dv.vulnerability_id = fasvf.vulnerability_id
WHERE
   dt.tag_type ilike 'custom';