SELECT
    ds.name AS site,
    da.ip_address,
    da.host_name,
    dos.description AS operating_system,
    dv.title,
    dv.severity,
    proofAsText(favi.proof)
FROM
    fact_asset_vulnerability_instance favi
    JOIN dim_vulnerability_solution dvs USING (vulnerability_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    JOIN dim_asset da USING (asset_id)
    JOIN dim_operating_system dos USING (operating_system_id)
    JOIN dim_site_asset dsa USING (asset_id)
    JOIN dim_site ds USING (site_id)
WHERE
    dv.title ilike '%log4j%'
    AND
    favi.proof ilike '%homebrew%'
