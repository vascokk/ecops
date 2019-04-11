-author("Vasco").

%% PCMM COPS Objects (SNum)
-define(PCMM_TRANSACTION_ID, 1).
-define(PCMM_AM_ID, 2).
-define(PCMM_SUBSCRIBER_ID, 3).
-define(PCMM_GATE_ID, 4).
-define(PCMM_GATE_SPEC, 5).
-define(PCMM_CLASSIFIERS, 6).
-define(PCMM_TRAFFIC_PROFILE, 7).
-define(PCMM_EVENT_GENERATION_INFO, 8).
-define(PCMM_VOLUME_BASED_USAGE_LIMIT, 9).
-define(PCMM_TIME_BASED_USAGE_LIMIT, 10).
-define(PCMM_OPAQUE_DATA, 11).
-define(PCMM_GATE_TIME_INFO, 12).
-define(PCMM_GATE_USAGE_INFO, 13).
-define(PCMM_PACKET_CABLE_ERROR, 14).
-define(PCMM_GATE_STATE, 15).
-define(PCMM_VERSION_INFO, 16).
-define(PCMM_PSID, 17).
-define(PCMM_SYNCH_OPTIONS, 18).
-define(PCMM_MSG_RECEIPT_KEY, 19).
-define(PCMM_USER_ID, 21).
-define(PCMM_SHARED_RESOURCE_ID, 22).

-record(pcmm_object, {
  length,
  s_num,
  s_type,
  content
}).

-record(transaction_id,{
  transaction_id,
  command_type
}).

-record(am_id,{
  app_type,
  app_mgr_tag
}).

-record(subscriber_id,{
  subscriber_id
}).

-record(gate_spec,{
  reserved = 0,
  dscp_overwrite,
  gate,
  dscp,
  dscp_mask,
  session_class_id,
  t1,
  t2,
  t3,
  t4
}).

-record(classifier, {
  protocol_id,
  dscp,
  dscp_mask,
  src_ip_addr,
  dst_ip_addr,
  src_port,
  dst_port,
  priority,
  reserved
}).

-record(extended_classifier, {
  protocol_id,
  dscp,
  dscp_mask,
  src_ip_adr,
  src_ip_mask,
  dst_ip_addr,
  dst_ip_mask,
  src_port_start,
  src_port_end,
  dst_port_start,
  dst_port_end,
  classifier_id,
  priority,
  activation_state,
  action,
  reserved = 0
}).

-record(ipv6_classifier, {
  reserved_1 = 0,
  flags,
  tc_low,
  tc_high,
  tc_mask,
  flow_label,
  next_header_type,
  src_prefix_len,
  dst_prefix_len,
  src_ip,
  dst_ip,
  src_port_start,
  src_port_end,
  dst_port_start,
  dst_port_end,
  classifier_id,
  priority,
  activation_state,
  action,
  reserved_2 = 0
}).

-record(flow_spec, {
  envelope,
  service_number,
  reserved = 0,
  authorized_envelope = {},
  reserved_envelope = {},
  commited_envelope = {}
}).

-record(flow_spec_envelope, {
  bucket_rate,
  bucket_size,
  peak_rate,
  min_policed_unit,
  max_packet_size,
  rate,
  slack_term
}).

-record(version_info,{
  major,
  minor
}).

-record(gate_id, {
  gate_id
}).