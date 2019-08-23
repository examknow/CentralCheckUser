-- Tables for the CheckUser extension
-- vim: autoindent syn=mysql sts=2 sw=2

CREATE TABLE /*_*/cu_changes (
  -- Primary key
  gcuc_id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,

  -- When pages are renamed, their RC entries do _not_ change.
  gcuc_namespace int NOT NULL default '0',
  gcuc_title varchar(255) binary NOT NULL default '',

  -- user.user_id
  gcuc_user INTEGER NOT NULL DEFAULT 0,
  gcuc_user_text VARCHAR(255) NOT NULL DEFAULT '',

  -- Edit summary
  gcuc_actiontext varchar(255) binary NOT NULL default '',
  gcuc_comment varchar(255) binary NOT NULL default '',
  gcuc_minor bool NOT NULL default '0',

  -- Key to page_id (was cur_id prior to 1.5).
  -- This will keep links working after moves while
  -- retaining the at-the-time name in the changes list.
  gcuc_page_id int(10) unsigned NOT NULL default '0',

  -- rev_id of the given revision
  gcuc_this_oldid int(10) unsigned NOT NULL default '0',

  -- rev_id of the prior revision, for generating diff links.
  gcuc_last_oldid int(10) unsigned NOT NULL default '0',

  -- Edit/new/log
  gcuc_type tinyint(3) unsigned NOT NULL default '0',

  -- Event timestamp
  gcuc_timestamp CHAR(14) NOT NULL default '',

  -- IP address, visible
  gcuc_ip VARCHAR(255) NULL default '',

  -- IP address as hexidecimal
  gcuc_ip_hex VARCHAR(255) default NULL,

  -- XFF header, visible, all data
  gcuc_xff VARCHAR(255) BINARY NULL default '',

  -- XFF header, last IP, as hexidecimal
  gcuc_xff_hex VARCHAR(255) default NULL,

  -- User agent
  gcuc_agent VARCHAR(255) BINARY default NULL,

  -- Private Data
  gcuc_private MEDIUMBLOB default NULL
) /*$wgDBTableOptions*/;

CREATE INDEX /*i*/gcuc_ip_hex_time ON /*_*/gcu_changes (gcuc_ip_hex,gcuc_timestamp);
CREATE INDEX /*i*/gcuc_user_ip_time ON /*_*/gcu_changes (gcuc_user,gcuc_ip,gcuc_timestamp);
CREATE INDEX /*i*/gcuc_xff_hex_time ON /*_*/gcu_changes (gcuc_xff_hex,gcuc_timestamp);
CREATE INDEX /*i*/gcuc_timestamp ON /*_*/gcu_changes (gcuc_timestamp);
