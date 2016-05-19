/**
Detected Client:
Method Name: CTIS.GetDetectedClient
Input Data:
timeline,detection
Output Data: 
<row 
guid="04d59668-68b0-4d6c-a7be-6785d46ab19a" 
country="Chile" 
region="LAR"  (region_Ext)
blob_count="297348" (detection,timeline)
lastupdate="10/28/2011 12:00:00 AM" 
--detectionlist="<rows><row detection=&quot;WORM_DOWNAD.AD&quot;/></rows>" 

step1:
因為是count某個detection,所以detection就不用是欄位了
group by guid
filter by timeline,region,detection

guid1,timeline,region,detection
guid2,timeline,region,detection

step2:
top 100 guid then the last record's (timeline,region,detection) lastupdate,country,region.

2014-04-09 05:55:49,736 
2014-04-09 06:03:28,066
8mins
/>
*/
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

A = LOAD 'date://2014/04/06/01' using VsapiProtobufLoader();
/*B = FOREACH A GENERATE
        DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,
        DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a' ) as timestamp:long,
        DateParser('2014/03/24 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a')  as st:long,
        DateParser('2014/03/31 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a') as ed:long,
        TRIM(Location(value.addr.peerIp).countryCode) as CountryCode,
        flatten(value.blob.virusinfo.detectionname) as detection,
        value.guid as guid;
*/
B = FOREACH A GENERATE
	flatten(value.blob.virusinfo.detectionname) as detection,
	TRIM(Location(value.addr.peerIp).countryCode) as CountryCode,
        TRIM(Location(value.addr.peerIp).countryName) as countryName,
        --DateParser('2014/03/24 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a')  as st:long,
        --DateParser('2014/03/31 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a') as ed:long,
	DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a' ) as timestamp:long,
	value.guid as guid;
C = filter B by detection matches 'HI_Generic.017';
--and timestamp-st >(long)0 and timestamp-ed <=(long)0 ;
B1 = group C by (detection,CountryCode,countryName,guid);
B2 = foreach B1 GENERATE  FLATTEN(group) AS (detection,CountryCode,countryName,guid), 
COUNT(C) as blob_cnt;
D = ORDER B2 BY blob_cnt DESC;
X = LIMIT D 100;

R = JOIN X by (detection,CountryCode,countryName,guid), C by (detection,CountryCode,countryName,guid);
R1 = foreach R GENERATE X::detection,X::CountryCode,X::countryName,X::guid,X::blob_cnt,C::timestamp;
R2 = group R1 by (detection,CountryCode,countryName,guid,blob_cnt);
R3 = foreach R2 GENERATE FLATTEN(group) as (detection,CountryCode,countryName,guid,blob_cnt),
DateFormat(MAX(R1.timestamp),'yyyy-MM-dd HH:mm:ss a') as lastupdate;
--X2= LIMIT R3 100;

/*
(HI_Generic.017,JP,00f6c38d-3303-463e-9924-5db5b22dfb44,599,2014-03-30 01:25:42
(HI_Generic.017,JP,0bb92ab4-ff05-484e-a551-7f3b93731fba,699,2014-03-30 01:16:30
*/

A2 = load 'country_ext.csv' USING PigStorage(',') as (CountryName:chararray,CountryCode:chararray,Region_Ext:chararray);
R4 = JOIN R3 by TRIM(CountryCode), A2 by TRIM(CountryCode);
E = foreach R4 GENERATE 
guid,
countryName,
A2::Region_Ext as region,
blob_cnt ,
lastupdate;
D2 = ORDER E BY blob_cnt DESC;
E1 = LIMIT D2 20;
store E1 into '20140406_TOP20_Detection_V3' using PigStorage(',');



--test(過濾掉GUID重複的做法)
B2 = foreach B1 
{
DW = distinct B.guid;
GENERATE  FLATTEN(group) AS (detection,CountryCode), 
COUNT(DW) as blob_cnt;
--DateFormat(max(timestamp),'yyyy-MM-dd HH:mm:ss a') as lastupdate;	
};
D = ORDER B2 BY blob_cnt DESC;
X = LIMIT D 100;
store X into '20140330_TOP20_Detection' using PigStorage(',');