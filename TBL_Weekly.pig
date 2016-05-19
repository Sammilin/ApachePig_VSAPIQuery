--start=2014-03-26 09:03:50,915
--End=2014-03-26 09:58:21,754 
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A1= load 'date://2014/03/17' using VsapiProtobufLoader();
A2 = load 'date://2014/03/18' using VsapiProtobufLoader();
A3 = load 'date://2014/03/19' using VsapiProtobufLoader();
A4 = load 'date://2014/03/20' using VsapiProtobufLoader();
A5 = load 'date://2014/03/21' using VsapiProtobufLoader();
A6 = load 'date://2014/03/22' using VsapiProtobufLoader();
A7 = load 'date://2014/03/23' using VsapiProtobufLoader();
X = UNION A1,A2,A3,A4,A5,A6,A7;

B = FOREACH X GENERATE
        flatten(value.blob.virusinfo.detectionname) as detection,
        Location(value.addr.peerIp).countryCode as country_code,
        Location(value.addr.peerIp).region as state_code,
        value.guid as guid ;

B1 = group B by (detection,country_code,state_code,guid);
C = foreach B1 GENERATE '2014/03/17' as rcvdate,FLATTEN(group) AS (detection,country_code,state_code,guid), COUNT(B.guid) as guid_cnt;

store C into '20140317_weekly' using PigStorage(',');


--test.pig
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
--X = LOAD 'date://2014/03/13/01' using VsapiProtobufLoader();
X = load 'time.txt' as (dt:datetime);
B = FOREACH X GENERATE 
DaysBetween(dt,(datetime)ToDate('2014-03-13', 'yyyy-MM-dd')) as checkdt;
--MilliSecondsBetween(GetMilliSecond(dt),GetMilliSecond((datetime)ToDate('2014-03-13', 'yyyy-MM-dd'))) as checkd;

--B1 = group B by (dt,guid);
--C = FOREACH B GENERATE 
--
--guid;

--A = Limit B 10;
DUMP B;


(0)
(1)
(2)
(-2)
(0)

2014-03-13T00:00:00.000-13:00
2014-03-13T12:00:00.000-13:00
2014-03-15T00:00:00.000-13:00
2014-03-10T09:11:00.000-13:00
2014-03-12T00:00:00.000-13:00


2014-03-13
2014-03-13
2014-03-15
2014-03-10
2014-03-12

