SELECT 
    da.host_name AS "Asset Name",
    da.ip_address AS "Asset IP Address",
    dos.name AS "Asset OS Name",
    dht.name AS "Asset Type",
    dos.family AS "Asset OS Family",
    da.location AS "Location",
    dv.vulnerability_id AS "Vulnerability ID",
    dv.title AS "Vulnerability Title",
    dv.description AS "Vulnerability Description",
    favf.proof AS "Vulnerability Proof",
    DATE_PART('day', NOW() - favf.first_discovered) AS "Vulnerability Age",
    substring(dv.title from 'CVE-[0-9]+-[0-9]+') AS "Vulnerability CVE ID",
    dv.cvss_score AS "Vulnerability CVSS Score",
    dv.cvss_v3_score AS "Vulnerability CVSSv3 Score",
    dv.riskscore AS "Vulnerability Risk Score",
    fas.last_assessed_for_vulnerabilities AS "Vulnerability Last Scan Date",
    far.remediation_date AS "Vulnerability Remediation Date",
    favf.first_discovered AS "Vulnerable Since"
FROM 
    fact_asset_vulnerability_finding favf
JOIN 
    dim_asset da ON favf.asset_id = da.asset_id
JOIN 
    dim_operating_system dos ON da.operating_system_id = dos.operating_system_id
JOIN 
    dim_host_type dht ON da.host_type_id = dht.host_type_id
JOIN 
    dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
JOIN 
    fact_asset_scan fas ON da.asset_id = fas.asset_id
JOIN 
    fact_asset_vulnerability_remediation_date far ON favf.asset_id = far.asset_id 
    AND favf.vulnerability_id = far.vulnerability_id
WHERE 
    far.remediation_date IS NOT NULL
    AND far.remediation_date BETWEEN '2024-09-04' AND '2024-09-06'
ORDER BY 
    far.remediation_date DESC;
