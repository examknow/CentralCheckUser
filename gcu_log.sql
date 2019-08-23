-- GlobalCheckUser log table
-- vim: autoindent syn=mysql sts=2 sw=2

CREATE TABLE /*_*/gcu_log (
  -- Unique identifier
  gcul_id int unsigned not null primary key auto_increment,

  -- Timestamp of CheckUser action
  gcul_timestamp binary(14) not null,

  -- User who performed the action
  gcul_user int unsigned not null,
  gcul_user_text varchar(255) binary not null,

  -- Wiki On Which The Check Was Ran
  gcul_user_text varchar(255) binary not null,
  -- Reason given
  gcul_reason varchar(255) binary not null,

  -- String indicating the type of query, may be "userips", "ipedits", "ipusers", "ipedits-xff", "ipusers-xff"
  gcul_type varbinary(30) not null,

  -- Integer target, interpretation depends on cul_type
  -- For username targets, this is the user_id
  gcul_target_id int unsigned not null default 0,

  -- Text target, interpretation depends on cul_type
  gcul_target_text blob not null,

  -- If the target was an IP address, this contains the hexadecimal form of the IP
  gcul_target_hex varbinary(255) not null default '',
  -- If the target was an IP range, these fields contain the start and end, in hex form
  gcul_range_start varbinary(255) not null default '',
  gcul_range_end varbinary(255) not null default ''
) /*$wgDBTableOptions*/;

CREATE INDEX /*i*/gcul_user ON /*_*/gcu_log (gcul_user, gcul_timestamp);
CREATE INDEX /*i*/gcul_type_target ON /*_*/gcu_log (gcul_type, gcul_target_id, gcul_timestamp);
CREATE INDEX /*i*/gcul_target_hex ON /*_*/gcu_log (gcul_target_hex, gcul_timestamp);
CREATE INDEX /*i*/gcul_range_start ON /*_*/gcu_log (gcul_range_start, gcul_timestamp);
CREATE INDEX /*i*/gcul_timestamp ON /*_*/gcu_log (gcul_timestamp);
