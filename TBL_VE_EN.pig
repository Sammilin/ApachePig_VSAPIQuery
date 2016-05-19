SELECT [virus_name]
 ,[24h_guid]
 ,[07d_guid]
 ,[30d_guid]
 ,[24h_records]
 ,[07d_records]
 ,[30d_records]
 ,[first_feedback_date]
 ,[last_feedback_date]
 ,[regin]
 ,[all_guid]
 ,[all_records]
 ,[first_feedback_locid]
 ,[last_feedback_locid]
 ,[malware_family] -->和malware_group的差別是?
 ,[is_Silent]
 ,[malware_group]
 FROM [SPN_THREAT].[SPN].[TBL_VE_EN]
GO

set job.name            '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
set job.monitor.name    '[CTIS] Get TBL_VSAPI_SHA1_INFO_COUNTRY_ST';
A1 = load 'date://2013/09/01/10' using VsapiProtobufLoader(); 
A = FOREACH A1 GENERATE 
flatten(value.blob.virusinfo.detectionname) as detectionname, 
value.addr.peerIp as ip,
value.guid as guid , 
	value.product.id as product_id;

A2 = FOREACH A GENERATE REGEX_EXTRACT(detectionname, '[a-zA-Z]*_[a-zA-Z]*',0) as malware_family, cc;
B = group A2 by (detectionname, cc);
C = foreach B generate FLATTEN(group), COUNT(A2) as count;

D = order C by count desc;
 dump D;