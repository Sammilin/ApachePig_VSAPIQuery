/*
SELECT [detection],[rcvdate]
 ,[Region_I] -- (EMEA / JAPAN / NABU / APAC / LAR --> mapping to TBL_REF_COUNTRY)
 ,[Region] -- (EUROPE / North AMERICA / APAC / AFRICA / Mid & South AMERICA --> mapping to TBL_REF_COUNTRY_EXTERNAL)
 ,[blob_count]
 ,[guid_count]
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_SPN_MAP_DETECTION_INFO_CACHE]
*/

/* Result
HI_Generic.017,2014/03/09,EMEA,EUROPE,5,5
HI_Generic.017,2014/03/09,EMEA,EUROPE,15,3
HI_Generic.017,2014/03/09,LAR,North AMERICA,3,3
HEUR_PDFEXP.A,2014/03/09,LAR,North AMERICA,3,3
HI_Generic.017,2014/03/09,LAR,North AMERICA,8,8
HI_Generic.017,2014/03/09,LAR,North AMERICA,3,3
HI_Generic.017,2014/03/09,EMEA,AFRICA,7,7
HI_Generic.017,2014/03/09,EMEA,AFRICA,5,4
HI_Generic.017,2014/03/09,EMEA,AFRICA,5,1
ADW_ESCORT,2014/03/09,EMEA,AFRICA,3,3
HI_Generic.017,2014/03/09,EMEA,AFRICA,5,5
HA_Vbfus,2014/03/09,EMEA,AFRICA,7,7
*/

--TBL_CACHE.pig
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A = load 'date://2014/03/09/00' using VsapiProtobufLoader();
B = FOREACH A GENERATE
	flatten(value.blob.virusinfo.detectionname) as detection,
	value.addr.peerIp as ip,
    value.guid as guid,
	DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate  ;
B1 = group B by (detection,ip,rcvdate,guid);
B2 = foreach B1 GENERATE  FLATTEN(group) AS (detection,ip,rcvdate,guid), COUNT(B) as guid_cnt;

C = FOREACH A GENERATE
	flatten(value.blob.virusinfo.detectionname) as detection,
	value.addr.peerIp as ip,
	DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate  ;
C1 = group C by (detection,ip,rcvdate);
C2 = foreach C1 GENERATE  FLATTEN(group) AS (detection,ip,rcvdate), COUNT(C) as blob_cnt;

Result = JOIN C2 by (detection,ip,rcvdate), B2 by (detection,ip,rcvdate);
D = foreach Result GENERATE 
C2::detection,
C2::rcvdate,
--Location(ip).latitude as latitude,
--Location(ip).longitude as longitude,
TRIM(Location(C2::ip).countryCode)  as CountryCode,
blob_cnt ,
guid_cnt;

A1 = load 'country.csv' USING PigStorage(',') as (CountryName:chararray,CountryCode:chararray,Region:chararray);
A2 = load 'country_ext.csv' USING PigStorage(',') as (CountryName:chararray,CountryCode:chararray,Region_Ext:chararray);
R2 = JOIN D by TRIM(CountryCode), A1 by TRIM(CountryCode), A2 by TRIM(CountryCode);
E = foreach R2 GENERATE 
detection,
rcvdate,
A1::Region as region_I,
A2::Region_Ext as region,
blob_cnt ,
guid_cnt;
store E into '20140309_TBL_CACHE' using PigStorage(','); 