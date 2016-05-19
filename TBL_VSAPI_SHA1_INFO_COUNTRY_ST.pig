--SELECT [rcvdate]
-- ,[hour]
-- ,[file_sha1]
-- ,[product_id]
-- ,[country_code]
-- ,[state_code]
-- ,[guid]
-- ,[pguid]
-- FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_SHA1_INFO_COUNTRY_ST]
--GO

set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

A = load 'date://2014/03/09/08' using VsapiProtobufLoader();
B = FOREACH A GENERATE 
ByteArrayToHex(value.blob.filesha1) as file_sha1 , 
value.addr.peerIp as ip,
value.guid as guid , value.pguid as pguid ;
B1 = group B by (file_sha1, ip, guid, pguid);
B2 = foreach B1 GENERATE FLATTEN(group) AS (file_sha1, ip, guid, pguid), COUNT(B) as count;

A1 = load 'PGUIDList.txt' as (pguid:chararray);
Result = JOIN B2 by pguid, A1 by pguid;
D = foreach Result GENERATE file_sha1,Location(ip).countryCode as 
country_code,guid,B2::pguid,product_id,'2014/02/23' as rcvdate,
'08' as hour,Location(ip).region as state_code,count;
store D into '201403030852' using PigStorage(',');


