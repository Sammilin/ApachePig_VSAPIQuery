/* Top 20 file full path:
Method Name: GetTop20SHA1ByMalware
Output Date: 
<row file_fullpath="C:\WINDOWS\System32\x" guid_count="69095" guid_list="" filesha1_list="" />
Map UI used [file_fullpath] and [guid_count].

Runtime: 2014-04-02 09:40:47,519 - 2014-04-02 09:44:22,868, 4mins (1hr)
		 2014-04-02 09:49:27,970 - 2014-04-02 09:55:31,248, 6mins (1day)
		 2014-04-02 09:58:26,038 - 2014-04-02 10:20:47,183, 22mins(1month)

--2014-04-07 06:26:14,630 - 2014-04-07 06:36:38,319 (by monthly)

date://2014/04再抓區間
fillpath_1          2014-04-10 09:22:20,769  - 2014-04-10 10:59:46,338 (37mins)

date://2014/04/{01,02,03,04,05,06,07}
(新用法)filepath_2  
2014-04-10 10:04:55,255  - 2014-04-10 11:15:44,417  (1hr,11mins) ->2隻同時在跑時
2014-04-11 02:04:29,091 - 2014-04-11 02:24:55,224 (20 mins)

SPN.FNC_RegExReplace( 
SPN.FNC_RegExReplace( 
SPN.FNC_RegExReplace(@file_fullpath,N'[D-Z]{1}:','[D-Z]:') 
,N'(?<=\\users\\|\\Documents\sand\sSettings\\|\\DOCUME~\d\\)(.\B)*(.\b)*','[UserName]\') 
,N'\\\\\?\\','')
2014-04-10 03:45:11,682 -2014-04-10 03:49:24,798 about 4mins(by hour)

一次多小時
A = LOAD 'date://2014/04/05/{01,02}' using VsapiProtobufLoader(); 

A = LOAD 'date://2014/04/09/{16,17,18,19,20,21,22,23}' using VsapiProtobufLoader(); 

A = LOAD '/SPN_fblog/2014/04/09/{16,17,18,19,20,21,22,23}/vsapi_001/*,/SPN_fblog/2014/04/10/{00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,16}/vsapi_001/*' using VsapiProtobufLoader();
B = limit A 10;
dump B;


跨月的
A = LOAD '/SPN_fblog/2014/03/{25,26,27,28}/vsapi_001/*,/SPN_fblog/2014/04/{01,02,03}/vsapi_001/*' using VsapiProtobufLoader();
B = limit A 10;
dump B;


A= LOAD '/SPN_fblog/2014/03/31/0{0..5}/vsapi_001/*' using VsapiProtobufLoader();
B = limit A 10;
dump B;

*/
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

--A = LOAD 'date://2014/04/0{1..7}' using VsapiProtobufLoader();
A = LOAD 'date://2014/04/{01,02,03,04,05,06,07}' using VsapiProtobufLoader();
B = FOREACH A GENERATE
        flatten(value.blob.virusinfo.detectionname) as detection,
        --DateParser('2014/03/24 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a')  as st:long,
        --DateParser('2014/03/31 00:00:00 AM', 'yyyy/MM/dd HH:mm:ss a') as ed:long,
        value.blob.filefullpath as file_fullpath,
        value.guid as guid;

B1 = filter B by detection matches 'HI_Generic.017' and timestamp-st >(long)0 and timestamp-ed <=(long)0 and file_fullpath is not null;

C = FOREACH B1 GENERATE 
FLATTEN(REPLACE(REPLACE(REPLACE(TRIM(file_fullpath) ,'[D-Z]{1}:','[D-Z]:'), 
'(?ix)(?<=\\\\Users\\\\|\\\\Documents\\sand\\sSettings\\\\All\\sUsers\\\\Documents\\\\|\\\\Documents\\sand\\sSettings\\\\(?!All\\sUsers\\\\Documents\\\\)|\\\\DOCUME~\\d\\\\)(.\\B)*(.\\b)*'
,'[UserName]\\\\'),
'(\\\\{2,}\\?\\\\)','')) as filefullpath,guid;


C1 = group C by (filefullpath);
D = FOREACH C1 GENERATE FLATTEN(group) AS (filefullpath),COUNT(C) as guid_cnt;
D1 = ORDER D BY guid_cnt DESC;
X = LIMIT D1 20;
DUMP X;
--store X into '201403_TOP20_SHA1_FilePath' using PigStorage(',');




//TOP_FullPath.pig
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

A = LOAD 'date://2014/04/05/01' using VsapiProtobufLoader();
B = FOREACH A GENERATE
        value.blob.filefullpath as file_fullpath,
        value.guid as guid;
B1 = FILTER B by file_fullpath is not null;

C = FOREACH B1 GENERATE
REPLACE(REPLACE(REPLACE(file_fullpath ,'[D-Z]{1}:','[D-Z]:'), 
'(?<=\\\\Users\\\\|\\\\Documents\\sand\\sSettings\\\\|\\\\DOCUME~\\d\\\\)(.\\B)*(.\\b)*','[UserName]\\\\'),
'(\\\\{2,}\\?\\\\)','') as filefullpath,
guid;

C1 = group C by (filefullpath,guid);
D = FOREACH C1 GENERATE FLATTEN(group) AS (filefullpath,guid),COUNT(C) as guid_cnt;
D1 = ORDER D BY guid_cnt DESC;
X = LIMIT D1 20;
X = LIMIT C1 100;

DUMP X;
--store X into '201403_TOP20_SHA1_FilePath' using PigStorage(',');

--TOP_FullFile
set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';

A1 = LOAD 'date://2014/04/05/01' using VsapiProtobufLoader();
A2 = FOREACH A1 GENERATE flatten(value.blob.virusinfo.detectionname) as detectionname , value.blob.filefullpath as filefullpath, value.guid as guid;
--ByteArrayToHex(value.blob.filesha1) as filesha1;

A3 = FOREACH A2 GENERATE REGEX_EXTRACT(detectionname, '(.*)_(.*)', 2) as detectionname, filefullpath,guid;
A4 = FOREACH A3 GENERATE REGEX_EXTRACT(detectionname, '(.*)\\.(.*)', 1) as detectionname, filefullpath,guid;

/*
2014-04-09 06:48:23,931
2014-04-09 06:52:34,919 4mins
*/
--例如"(?<=foo)bar"，找接在foo之後的"bar"。還有裡面的文字必須已知長度
FLATTEN(REPLACE(TRIM(file1), '(?<=(users)|(Documents\\sand\\sSettings)|(DOCUME~\\d\\))(.\\B)*(.\\b)*','[UserName]\\\\')) as file2,


A3 = FOREACH A2 GENERATE REGEX_EXTRACT(filefullpath ,'(\\\\{2,}\\?\\\\)',1) as filefullpath, detectionname,guid;
A4 = FOREACH A2 REPLACE(detectionname ,'(\\\\{2,}\\?\\\\)',1) as detectionname, detectionname,guid;
--目前這個版本只剩All Users的問題
--A = FOREACH A2 GENERATE REPLACE(REPLACE(REPLACE(filefullpath ,'[D-Z]{1}:','[D-Z]:'), '(?<=\\\\Users\\\\|\\\\Documents\\sand\\sSettings\\\\|\\\\DOCUME~\\d\\\\)(.\\B)*(.\\b)*','[UserName]\\\\'),'(\\\\{2,}\\?\\\\)','') as filefullpath, detectionname,guid;

--無敵版本, 謝謝YY
A = FOREACH A2 GENERATE REPLACE(REPLACE(REPLACE(filefullpath ,'[D-Z]{1}:','[D-Z]:'), 
'(?ix-msn)(?<=\\\\Users\\\\|\\\\Documents\\sand\\sSettings\\\\All\\sUsers\\\\Documents\\\\|\\\\Documents\\sand\\sSettings\\\\(?!All\\sUsers\\\\Documents\\\\)|\\\\DOCUME~\\d\\\\)(.\\B)*(.\\b)*'
,'[UserName]\\\\'),
'(\\\\{2,}\\?\\\\)','') as filefullpath, detectionname,guid;

B=  GROUP A BY (filefullpath,detectionname);
C = foreach B {
    DI = distinct A.guid;
    generate group , COUNT(DI) as CNT ;};
D = order C by CNT desc;
E = LIMIT D 20;
DUMP E;
--store E into 'hackathon/Q7_7';

