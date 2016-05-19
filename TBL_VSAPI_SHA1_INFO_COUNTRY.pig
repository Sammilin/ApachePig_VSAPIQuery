/*
SELECT [rcvdate]
 ,[detection]
 ,[country_code]
 ,[state_code]
 ,[guid_cnt] ¡V unique guid count
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_DETECTION_INFO_COUNTRY]
GO
*/

set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A = load 'date://2014/03/09' using VsapiProtobufLoader();
B = FOREACH A GENERATE 
	--ByteArrayToHex(value.blob.filesha1) as file_sha1 , 
	DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,  
	flatten(value.blob.virusinfo.detectionname) as detection,
	value.addr.peerIp as ip,
	--Location(ip).countryCode as country_code,
	--Location(ip).region as state_code,
	value.guid as guid,
B1 = group B by (rcvdate,detection,ip,pguid);
B2 = foreach B1 GENERATE FLATTEN(group) AS (rcvdate,detection,ip,pguid), COUNT(B) as guid_cnt;
C = foreach B2 GENERATE 
rcvdate,
detection,
Location(ip).countryCode as country_code,
Location(ip).region as state_code,
guid_cnt;
store C into '20140309_COUNTRY' using PigStorage(',');

 
