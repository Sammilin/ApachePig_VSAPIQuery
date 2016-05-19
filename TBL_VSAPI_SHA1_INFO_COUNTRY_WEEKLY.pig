/*
SELECT [rcvdate]
 ,[detection]
 ,[country_code]
 ,[state_code]
 ,[guid_cnt]   unique guid count
 FROM [SPN_MART_SHA1_INFO].[SPN].[TBL_VSAPI_DETECTION_INFO_COUNTRY_WEEKLY] 
 */
--2014-03-17 07:47:33,135 start
--2014-03-17 08:00:35,601 end

--2014-03-17 08:16:53,035 start
--2014-03-17 08:57:30,157 end

weekly_4.pig
--2014-03-17 09:38:29,275 start


set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

/*A1 = LOAD 'date://2014/03/10/*' using VsapiProtobufLoader();
A2 = LOAD 'date://2014/03/11/*' using VsapiProtobufLoader();
A3 = load 'date://2014/03/12/*' using VsapiProtobufLoader();
A4 = load 'date://2014/03/13/*' using VsapiProtobufLoader();
A5 = load 'date://2014/03/14/*' using VsapiProtobufLoader();
A6 = load 'date://2014/03/15/*' using VsapiProtobufLoader();
A7 = load 'date://2014/03/16/*' using VsapiProtobufLoader();
X = UNION A1, A2,A3, A4,A5, A6,A7;
*/
X = LOAD 'date://2014/03/*/*' using VsapiProtobufLoader();
B = FOREACH X GENERATE 
	ToDate(DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy-MM-dd HH:mm:ss a'), 'yyyy-MM-dd HH:mm:ss')) as dt:datetime,
	flatten(value.blob.virusinfo.detectionname) as detection,
	--ByteArrayToHex(value.blob.filesha1) as file_sha1 , 
	--value.addr.peerIp as ip,
	Location(value.addr.peerIp).countryCode as country_code,
	Location(value.addr.peerIp).region as state_code,
	value.guid as guid ;
C = filter B by DaysBetween(dt,(datetime)ToDate('2014-03-10', 'yyyy-MM-dd')) >=(long)0 and
				DaysBetween(dt,(datetime)ToDate('2014-03-17', 'yyyy-MM-dd')) <(long)0;

--A = FOREACH C GENERATE detection,
--Location(ip).countryCode as country_code,
--Location(ip).region as state_code,
--guid;
B1 = group B by (detection,country_code,state_code,guid);
B2 = foreach B1 GENERATE FLATTEN(group) AS (detection,country_code,state_code,guid), COUNT(B.guid) as guid_cnt;
D = foreach B2 GENERATE 
'3th_week' as rcvdate,detection,
country_code,
state_code,
--Location(ip).countryCode as country_code,
--Location(ip).region as state_code,
guid_cnt;

store D into '201403_3rd_weekly' using PigStorage(',');


dt=current();
 DaysBetween(dt,(datetime)ToDate('2014-03-10', 'yyyy-MM-dd'))


--A1 = LOAD 'date://2014/03/01' using VsapiProtobufLoader();
--A2 = LOAD 'date://2014/03/02' using VsapiProtobufLoader();
--A3 = load 'date://2014/03/03/01' using VsapiProtobufLoader();
--A4 = load 'date://2014/03/04/01' using VsapiProtobufLoader();
--A5 = load 'date://2014/03/05/01' using VsapiProtobufLoader();
--A6 = load 'date://2014/03/06/01' using VsapiProtobufLoader();
--A7 = load 'date://2014/02/28/01' using VsapiProtobufLoader();
--X = UNION A1, A2,A3, A4,A5, A6,A7;
--X = UNION A1, A2;

--C = filter B by time >= DateParser('2012 05/16 01:10', 'yyyy MM/dd HH:mm') and time <= DateParser('2012 05/16 01:20', 'yyyy MM/dd HH:mm');



