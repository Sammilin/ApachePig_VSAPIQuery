/*
SELECT [rcvdate]
 ,[detection]
 ,[pguid]
 ,[blob_cnt]
 ,[guid_cnt]
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_detection_info_local]
GO
*/
--start:2014-03-19 07:28:49,379 
--end:2014-03-19 07:38:51

/*
2014-03-14,HA_Vbfus,fddf7f00-a450-4260-8a49-c552ac8cdb7a,212,1
2014-03-14,HA_Vbfus,fddf7f00-a450-4260-8a49-c552ac8cdb7a,212,3
2014-03-14,HA_Vbfus,fddf7f00-a450-4260-8a49-c552ac8cdb7a,212,3
2014-03-14,HA_Vbfus,fddf7f00-a450-4260-8a49-c552ac8cdb7a,212,1
2014-03-14,HI_Generic.017,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,15,2
2014-03-14,HI_Generic.017,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,15,2
2014-03-14,HI_Generic.017,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,15,7
2014-03-14,HI_Generic.017,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,15,2
2014-03-14,HI_Generic.017,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,15,2
2014-03-14,HT_AGENT_CF112859.UVPM,ff0ce33b-bb05-4aa4-ba1b-bc77c2c10c4c,1,1
*/


set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A = load 'date://2014/03/14/00' using VsapiProtobufLoader();

--Colculate guid_cnt;
B = FOREACH A GENERATE
        DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,
        flatten(value.blob.virusinfo.detectionname) as detection,
        Location(value.addr.peerIp).countryCode as country_code,
        Location(value.addr.peerIp).region as state_code,
        value.pguid as pguid,
        value.guid as guid ;
B1 = group B by (rcvdate,detection,country_code,state_code,pguid,guid);
B2 = foreach B1 GENERATE FLATTEN(group) AS (rcvdate,detection,country_code,state_code,pguid,guid), COUNT(B) as guid_cnt;

--Colculate blob_cnt;
C = FOREACH A GENERATE
        DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,
        flatten(value.blob.virusinfo.detectionname) as detection,
        Location(value.addr.peerIp).countryCode as country_code,
        Location(value.addr.peerIp).region as state_code,
        value.pguid as pguid;
C1 = group C by (rcvdate,detection,country_code,state_code,pguid);
C2 = foreach C1 GENERATE FLATTEN(group) AS (rcvdate,detection,country_code,state_code,pguid), COUNT(C) as blob_cnt;

--joing B2 and C2
Result = JOIN C2 by (rcvdate,detection,country_code,state_code,pguid), B2 by (rcvdate,detection,country_code,state_code,pguid);
D = foreach Result GENERATE
C2::rcvdate,
C2::detection,
C2::pguid,
blob_cnt ,
guid_cnt;

--Match with PGUID.txt
A1 = load 'PGUIDList.txt' as (pguid:chararray);
Result = JOIN D by pguid, A1 by pguid;
E = foreach Result GENERATE
rcvdate,detection,
A1::pguid,
blob_cnt,guid_cnt;
store E into '20140314_Local_4' using PigStorage(',');
