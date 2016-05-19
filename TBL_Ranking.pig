-- ONLY ZG / Premium pguid Needed. Group all other data into record with NULL pguid
/*SELECT [rcvdate]
 ,[detection]
 ,[file_full_id] (no)
 ,[file_sha1]
 ,[loc_id] (no)
 ,[blob_cnt]
 ,[product_id] (no)
 ,[pguid]
 ,[guid] (no)
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_DETECTION_RANKING]
*/

set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A = load 'date://2014/03/09/00' using VsapiProtobufLoader();
B = FOREACH A GENERATE 
	DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,  
	flatten(value.blob.virusinfo.detectionname) as detection,
	ByteArrayToHex(value.blob.filesha1) as file_sha1 , 
	value.pguid as pguid;
B1 = group B by (rcvdate,detection,file_sha1,pguid);
B2 = foreach B1 GENERATE FLATTEN(group) AS (rcvdate,detection,file_sha1,pguid), COUNT(B) as blob_cnt;
A1 = load 'PGUIDList.txt' as (pguid:chararray);
Result = JOIN B2 by pguid, A1 by pguid;
D = foreach Result GENERATE 
rcvdate,
detection,
'0' as file_full_id,
file_sha1,
'0' as loc_id,
blob_cnt,
'' as product_id,
A1::pguid,
'' as guid;
store D into '20140309_Ranking' using PigStorage(',');