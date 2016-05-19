/*
SELECT [rcvdate]
 ,[hour]
 ,[detection]
 ,[country_code]
 ,[state_code]
 ,[guid]
 ,[pguid]
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_DETECTION_INFO_COUNTRY_ST] 
 */

set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A = load 'date://2014/03/17/01' using VsapiProtobufLoader();

--Colculate guid_cnt;
B = FOREACH A GENERATE
        flatten(value.blob.virusinfo.detectionname) as detection,
        Location(value.addr.peerIp).countryCode as country_code,
        Location(value.addr.peerIp).region as state_code,
        value.guid as guid ,
        value.pguid as pguid;

--Match with PGUID.txt
A1 = load 'PGUIDList.txt' as (pguid:chararray);
Result = JOIN B by pguid, A1 by pguid;
C = foreach Result GENERATE
detection,country_code,state_code,guid,A1::pguid;

A2 = load 'country.csv' USING PigStorage(',') as (CountryName:chararray,CountryCode:chararray,Region:chararray);
R2 = JOIN C by TRIM(country_code), A2 by TRIM(CountryCode);
D = foreach R2 GENERATE
'2014-03-17' as rcvdate,'01' as hour,
detection,
'' as product_id,
country_code,state_code,
guid,pguid,
'' as malware_group, '' as malware_family,
A2::Region as region;

store D into '20140317_Detection_Country_ST_1' using PigStorage(',');