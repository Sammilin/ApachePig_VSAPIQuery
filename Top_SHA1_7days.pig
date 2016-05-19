/*
7 days Data
* Runtime:2014-04-02 08:03:15,148  - 2014-04-02 08:29:00,282   about:26 minutes
*/
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

A = LOAD 'date://2014/03' using VsapiProtobufLoader();
B = FOREACH A GENERATE
        DateFormat(DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a'), 'yyyy-MM-dd') as rcvdate,
        DateParser(value.timestamp.blobRcvUTC, 'yyyy/MM/dd HH:mm:ss a' ) as timestamp:long,
        DateParser('2014/03/24 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a')  as st:long,
        DateParser('2014/03/31 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a') as ed:long,
        ByteArrayToHex(value.blob.filesha1) as file_sha1 ,
        flatten(value.blob.virusinfo.detectionname) as detection,
        value.guid as guid;
C = filter B by detection matches 'HI_Generic.017' and timestamp-st >(long)0 and timestamp-ed <=(long)0 and file_sha1 is not null;
C1 = group C by (file_sha1,guid);
D = FOREACH C1 GENERATE FLATTEN(group) AS (file_sha1,guid),COUNT(C) as guid_cnt;
D1 = ORDER D BY guid_cnt DESC;
X = LIMIT D1 20;
store X into '201403027-30_TOP20_SHA1' using PigStorage(',');