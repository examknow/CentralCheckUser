<?php

use MediaWiki\MediaWikiServices;
use MediaWiki\Auth\AuthenticationResponse;

class CheckUserHooks {
	/**
	 * Hook function for RecentChange_save
	 * Saves user data into the gcu_changes table
	 * Note that other extensions (like AbuseFilter) may call this function directly
	 * @param RecentChange $rc
	 * @return bool
	 */
	public static function updateCheckUserData( RecentChange $rc ) {
		global $wgRequest, $wgGlobalCheckUserWikiId;

		/**
		 * RC_CATEGORIZE recent changes are generally triggered by other edits.
		 * Thus there is no reason to store checkuser data about them.
		 */
		if ( defined( 'RC_CATEGORIZE' ) && $rc->getAttribute( 'rc_type' ) == RC_CATEGORIZE ) {
			return true;
		}
		/**
		 * RC_EXTERNAL recent changes are not triggered by actions on the local wiki.
		 * Thus there is no reason to store checkuser data about them.
		 */
		if ( defined( 'RC_EXTERNAL' ) && $rc->getAttribute( 'rc_type' ) == RC_EXTERNAL ) {
			return true;
		}

		$attribs = $rc->getAttributes();
		// Get IP
		$ip = $wgRequest->getIP();
		// Get XFF header
		$xff = $wgRequest->getHeader( 'X-Forwarded-For' );
		list( $xff_ip, $isSquidOnly ) = self::getClientIPfromXFF( $xff );
		// Get agent
		$agent = $wgRequest->getHeader( 'User-Agent' );
		// Store the log action text for log events
		// $rc_comment should just be the log_comment
		// BC: check if log_type and log_action exists
		// If not, then $rc_comment is the actiontext and comment
		if ( isset( $attribs['rc_log_type'] ) && $attribs['rc_type'] == RC_LOG ) {
			$target = Title::makeTitle( $attribs['rc_namespace'], $attribs['rc_title'] );
			$context = RequestContext::newExtraneousContext( $target );

			$formatter = LogFormatter::newFromRow( $rc->getAttributes() );
			$formatter->setContext( $context );
			$actionText = $formatter->getPlainActionText();
		} else {
			$actionText = '';
		}

		$dbw = wfGetDB( DB_MASTER, $wiki = $wgGlobalCheckUserWikiId );
		$rcRow = [
			'gcuc_namespace'  => $attribs['rc_namespace'],
			'gcuc_title'      => $attribs['rc_title'],
			'gcuc_minor'      => $attribs['rc_minor'],
			'gcuc_user'       => $attribs['rc_user'],
			'gcuc_user_text'  => $attribs['rc_user_text'],
			'gcuc_actiontext' => $actionText,
			'gcuc_comment'    => $rc->getAttribute( 'rc_comment' ),
			'gcuc_this_oldid' => $attribs['rc_this_oldid'],
			'gcuc_last_oldid' => $attribs['rc_last_oldid'],
			'gcuc_type'       => $attribs['rc_type'],
			'gcuc_timestamp'  => $attribs['rc_timestamp'],
			'gcuc_ip'         => IP::sanitizeIP( $ip ),
			'gcuc_ip_hex'     => $ip ? IP::toHex( $ip ) : null,
			'gcuc_xff'        => !$isSquidOnly ? $xff : '',
			'gcuc_xff_hex'    => ( $xff_ip && !$isSquidOnly ) ? IP::toHex( $xff_ip ) : null,
			'gcuc_agent'      => $agent
		];
		# On PG, MW unsets cur_id due to schema incompatibilites. So it may not be set!
		if ( isset( $attribs['rc_cur_id'] ) ) {
			$rcRow['cuc_page_id'] = $attribs['rc_cur_id'];
		}

		Hooks::run( 'GlobalCheckUserInsertForRecentChange', [ $rc, &$rcRow ] );
		$dbw->insert( 'gcu_changes', $rcRow, __METHOD__ );

		return true;
	}

	/**
	 * Hook function to store password reset
	 * Saves user data into the gcu_changes table
	 *
	 * @param User $user Sender
	 * @param string $ip
	 * @param User $account Receiver
	 * @return bool
	 */
	public static function updateCUPasswordResetData( User $user, $ip, $account ) {
		global $wgRequest, $wgGlobalCheckUserWikiId;

		// Get XFF header
		$xff = $wgRequest->getHeader( 'X-Forwarded-For' );
		list( $xff_ip, $isSquidOnly ) = self::getClientIPfromXFF( $xff );
		// Get agent
		$agent = $wgRequest->getHeader( 'User-Agent' );
		$dbw = wfGetDB( DB_MASTER, $wiki = $wgGlobalCheckUserWikiId );
		$rcRow = [
			'gcuc_namespace'  => NS_USER,
            'gcuc_wiki' => $wgSitename,
			'gcuc_title'      => '',
			'gcuc_minor'      => 0,
			'gcuc_user'       => $user->getId(),
			'gcuc_user_text'  => $user->getName(),
			'gcuc_actiontext' => wfMessage( 'checkuser-reset-action', $account->getName() )
				->inContentLanguage()->text(),
			'gcuc_comment'    => '',
			'gcuc_this_oldid' => 0,
			'gcuc_last_oldid' => 0,
			'gcuc_type'       => RC_LOG,
			'gcuc_timestamp'  => $dbw->timestamp( wfTimestampNow() ),
			'gcuc_ip'         => IP::sanitizeIP( $ip ),
			'gcuc_ip_hex'     => $ip ? IP::toHex( $ip ) : null,
			'gcuc_xff'        => !$isSquidOnly ? $xff : '',
			'gcuc_xff_hex'    => ( $xff_ip && !$isSquidOnly ) ? IP::toHex( $xff_ip ) : null,
			'gcuc_agent'      => $agent
		];
		$dbw->insert( 'gcu_changes', $rcRow, __METHOD__ );

		return true;
	}

	/**
	 * Hook function to store email data.
	 *
	 * Saves user data into the cu_changes table.
	 * Uses a deferred update to save the data, because emails can be sent from code paths
	 * that don't open master connections.
	 *
	 * @param MailAddress $to
	 * @param MailAddress $from
	 * @param string $subject
	 * @param string $text
	 * @return bool
	 */
	public static function updateCUEmailData( $to, $from, $subject, $text ) {
		global $wgSecretKey, $wgRequest, $wgCUPublicKey, $GlobalCheckUserWikiId;

		if ( !$wgSecretKey || $from->name == $to->name ) {
			return true;
		} elseif ( wfReadOnly() ) {
			return true;
		}

		$userFrom = User::newFromName( $from->name );
		$userTo = User::newFromName( $to->name );
		$hash = md5( $userTo->getEmail() . $userTo->getId() . $wgSecretKey );
		// Get IP
		$ip = $wgRequest->getIP();
		// Get XFF header
		$xff = $wgRequest->getHeader( 'X-Forwarded-For' );
		list( $xff_ip, $isSquidOnly ) = self::getClientIPfromXFF( $xff );
		// Get agent
		$agent = $wgRequest->getHeader( 'User-Agent' );

		$dbr = wfGetDB( DB_REPLICA, $wiki = $wgGlobalCheckUserWikiId );
		$rcRow = [
			'gcuc_namespace'  => NS_USER,
			'gcuc_title'      => '',
			'gcuc_minor'      => 0,
			'gcuc_user'       => $userFrom->getId(),
			'gcuc_user_text'  => $userFrom->getName(),
			'gcuc_actiontext' =>
				wfMessage( 'globalcheckuser-email-action', $hash )->inContentLanguage()->text(),
			'gcuc_comment'    => '',
			'gcuc_this_oldid' => 0,
			'gcuc_last_oldid' => 0,
			'gcuc_type'       => RC_LOG,
			'gcuc_timestamp'  => $dbr->timestamp( wfTimestampNow() ),
			'gcuc_ip'         => IP::sanitizeIP( $ip ),
			'gcuc_ip_hex'     => $ip ? IP::toHex( $ip ) : null,
			'gcuc_xff'        => !$isSquidOnly ? $xff : '',
			'gcuc_xff_hex'    => ( $xff_ip && !$isSquidOnly ) ? IP::toHex( $xff_ip ) : null,
			'gcuc_agent'      => $agent
                        'gcuc_wiki' => $wgSitename
		];
		if ( trim( $wgCUPublicKey ) != '' ) {
			$privateData = $userTo->getEmail() . ":" . $userTo->getId();
			$encryptedData = new CheckUserEncryptedData( $privateData, $wgCUPublicKey );
			$rcRow = array_merge( $rcRow, [ 'gcuc_private' => serialize( $encryptedData ) ] );
		}

		$fname = __METHOD__;
		DeferredUpdates::addCallableUpdate( function () use ( $rcRow, $fname ) {
			$dbw = wfGetDB( DB_MASTER );
			$dbw->insert( 'gcu_changes', $rcRow, $fname );
		} );

		return true;
	}

	/**
	 * Hook function to store registration and autocreation data
	 * Saves user data into the cu_changes table
	 *
	 * @param User $user
	 * @param bool $autocreated
	 * @return true
	 */
	public static function onLocalUserCreated( User $user, $autocreated ) {
		return self::logUserAccountCreation(
			$user,
			$autocreated ? 'globalcheckuser-autocreate-action' : 'globalcheckuser-create-action'
		);
	}

	/**
	 * @param User $user
	 * @param string $actiontext
	 * @return bool
	 */
	protected static function logUserAccountCreation( User $user, $actiontext ) {
		global $wgRequest, $wgGlobalCheckUserWikiId;

		// Get IP
		$ip = $wgRequest->getIP();
		// Get XFF header
		$xff = $wgRequest->getHeader( 'X-Forwarded-For' );
		list( $xff_ip, $isSquidOnly ) = self::getClientIPfromXFF( $xff );
		// Get agent
		$agent = $wgRequest->getHeader( 'User-Agent' );
		$dbw = wfGetDB( DB_MASTER,  $wiki = $wgGlobalCheckUserWikiId );
		$rcRow = [
			'gcuc_page_id'    => 0,
			'gcuc_namespace'  => NS_USER,
			'gcuc_title'      => '',
			'gcuc_minor'      => 0,
			'gcuc_user'       => $user->getId(),
			'gcuc_user_text'  => $user->getName(),
			'gcuc_actiontext' => wfMessage( $actiontext )->inContentLanguage()->text(),
			'gcuc_comment'    => '',
			'gcuc_this_oldid' => 0,
			'gcuc_last_oldid' => 0,
			'gcuc_type'       => RC_LOG,
			'gcuc_timestamp'  => $dbw->timestamp( wfTimestampNow() ),
			'gcuc_ip'         => IP::sanitizeIP( $ip ),
			'gcuc_ip_hex'     => $ip ? IP::toHex( $ip ) : null,
			'gcuc_xff'        => !$isSquidOnly ? $xff : '',
			'gcuc_xff_hex'    => ( $xff_ip && !$isSquidOnly ) ? IP::toHex( $xff_ip ) : null,
			'gcuc_agent'      => $agent
		];
		$dbw->insert( 'gcu_changes', $rcRow, __METHOD__ );

		return true;
	}

	/**
	 * @param AuthenticationResponse $ret
	 * @param User $user
	 * @param string $username
	 */
	public static function onAuthManagerLoginAuthenticateAudit(
		AuthenticationResponse $ret, $user, $username
	) {
		global $wgRequest, $wgGlobalCheckUserLogLogins, $wgGlobalCheckUserWikiId;

		if ( !$wgGlobalCheckUserLogLogins ) {
			return;
		}

		if ( !$user ) {
			$user = User::newFromName( $username, 'usable' );
		}

		if ( !$user ) {
			return;
		}

		if ( $ret->status === AuthenticationResponse::FAIL ) {
			$msg = 'globalcheckuser-login-failure';
		} elseif ( $ret->status === AuthenticationResponse::PASS ) {
			$msg = 'globalcheckuser-login-success';
		} else {
			// Abstain, Redirect, etc.
			return;
		}

		$ip = $wgRequest->getIP();
		$xff = $wgRequest->getHeader( 'X-Forwarded-For' );
		list( $xff_ip, $isSquidOnly ) = self::getClientIPfromXFF( $xff );
		$agent = $wgRequest->getHeader( 'User-Agent' );
		$userName = $user->getName();
		$target = "[[User:$userName|$userName]]";
		$msg = wfMessage( $msg );
		$msg->params( $target );

		$dbw = wfGetDB( DB_MASTER,  $wiki = $wgGlobalCheckUserWikiId );
		$rcRow = [
			'gcuc_page_id'    => 0,
			'gcuc_namespace'  => NS_USER,
			'gcuc_title'      => '',
			'gcuc_minor'      => 0,
			'gcuc_user'       => 0,
			'gcuc_user_text'  => $ip,
			'gcuc_actiontext' => $msg->inContentLanguage()->text(),
			'gcuc_comment'    => '',
			'gcuc_this_oldid' => 0,
			'gcuc_last_oldid' => 0,
			'gcuc_type'       => RC_LOG,
			'gcuc_timestamp'  => $dbw->timestamp( wfTimestampNow() ),
			'gcuc_ip'         => IP::sanitizeIP( $ip ),
			'gcuc_ip_hex'     => $ip ? IP::toHex( $ip ) : null,
			'gcuc_xff'        => !$isSquidOnly ? $xff : '',
			'gcuc_xff_hex'    => ( $xff_ip && !$isSquidOnly ) ? IP::toHex( $xff_ip ) : null,
			'gcuc_agent'      => $agent
		];
		$dbw->insert( 'gcu_changes', $rcRow, __METHOD__ );
	}

	/**
	 * Hook function to prune data from the cu_changes table
	 * @return true
	 */
	public static function maybePruneIPData() {
		global $wgGlobalCheckUserWikiId;
		# Every 50th edit, prune the checkuser changes table.
		if ( 0 == mt_rand( 0, 49 ) ) {
			$fname = __METHOD__;
			DeferredUpdates::addCallableUpdate( function () use ( $fname ) {
				global $wgCUDMaxAge;

				$dbw = wfGetDB( DB_MASTER, $wiki = $wgGlobalCheckUserWikiId );
				$encCutoff = $dbw->addQuotes( $dbw->timestamp( time() - $wgCUDMaxAge ) );
				$ids = $dbw->selectFieldValues( 'gcu_changes',
					'gcuc_id',
					[ "gcuc_timestamp < $encCutoff" ],
					$fname,
					[ 'LIMIT' => 500 ]
				);

				if ( $ids ) {
					$dbw->delete( 'gcu_changes', [ 'gcuc_id' => $ids ], $fname );
				}
			} );
		}

		return true;
	}

	/**
	 * Locates the client IP within a given XFF string.
	 * Unlike the XFF checking to determine a user IP in WebRequest,
	 * this simply follows the chain and does not account for server trust.
	 *
	 * This returns an array containing:
	 *   - The best guess of the client IP
	 *   - Whether all the proxies are just squid/varnish
	 *
	 * @param string $xff XFF header value
	 * @return array (string|null, bool)
	 * @todo move this to a utility class
	 */
	public static function getClientIPfromXFF( $xff ) {
		global $wgUsePrivateIPs;

		if ( !strlen( $xff ) ) {
			return [ null, false ];
		}

		# Get the list in the form of <PROXY N, ... PROXY 1, CLIENT>
		$ipchain = array_map( 'trim', explode( ',', $xff ) );
		$ipchain = array_reverse( $ipchain );

		if ( class_exists( ProxyLookup::class ) ) { // MW 1.28+
			$proxyLookup = MediaWikiServices::getInstance()->getProxyLookup();
		} else {
			// This is kind of sketch, but is good enough for back-compat
			$proxyLookup = new IP();
		}

		$client = null; // best guess of the client IP
		$isSquidOnly = false; // all proxy servers where site Squid/Varnish servers?
		# Step through XFF list and find the last address in the list which is a
		# sensible proxy server. Set $ip to the IP address given by that proxy server,
		# unless the address is not sensible (e.g. private). However, prefer private
		# IP addresses over proxy servers controlled by this site (more sensible).
		foreach ( $ipchain as $i => $curIP ) {
			$curIP = IP::canonicalize( $curIP );
			if ( $curIP === null ) {
				break; // not a valid IP address
			}
			$curIsSquid = $proxyLookup->isConfiguredProxy( $curIP );
			if ( $client === null ) {
				$client = $curIP;
				$isSquidOnly = $curIsSquid;
			}
			if (
				isset( $ipchain[$i + 1] ) &&
				IP::isIPAddress( $ipchain[$i + 1] ) &&
				(
					IP::isPublic( $ipchain[$i + 1] ) ||
					$wgUsePrivateIPs ||
					$curIsSquid // bug 48919
				)
			) {
				$client = IP::canonicalize( $ipchain[$i + 1] );
				$isSquidOnly = ( $isSquidOnly && $curIsSquid );
				continue;
			}
			break;
		}

		return [ $client, $isSquidOnly ];
	}

#	public static function onLoadExtensionSchemaUpdates( DatabaseUpdater $updater ) {
#		$base = __DIR__ . '/..';
#		$dbType = $updater->getDB()->getType();
#		$isCUInstalled = $updater->tableExists( 'gcu_changes' );
#
#		$updater->addExtensionTable(
#			'gcu_changes', self::getTableFileName( $dbType, 'gcu_changes' )
#		);
#		$updater->addExtensionTable(
#			'gcu_log', self::getTableFileName( $dbType, 'gcu_log' )
#		);
#
#		if ( $dbType === 'mysql' ) {
#			$updater->addExtensionIndex(
#				'gcu_changes',
#				'gcuc_ip_hex_time',
#				"$base/archives/patch-cu_changes_indexes.sql"
#			);
#			$updater->addExtensionIndex(
#				'gcu_changes',
#				'gcuc_user_ip_time',
#				"$base/archives/patch-cu_changes_indexes2.sql"
#			);
#			$updater->addExtensionField(
#				'gcu_changes',
#				'gcuc_private',
#				"$base/archives/patch-cu_changes_privatedata.sql"
#			);
#		} elseif ( $dbType === 'postgres' ) {
#			$updater->addExtensionUpdate(
#				[ 'addPgField', 'cu_changes', 'cuc_private', 'BYTEA' ]
#			);
#		}
#
#		if ( !$isCUInstalled ) {
#			// First time so populate cu_changes with recentchanges data.
#			// Note: We cannot completely rely on updatelog here for old entries
#			// as populateCheckUserTable.php doesn't check for duplicates
#			$updater->addPostDatabaseUpdateMaintenance( 'PopulateCheckUserTable' );
#		}
#	}
#
	/**
	 * @param string $type DB type
	 * @param string $name Table name
	 * @return string
	 */
	private static function getTableFileName( $type, $name ) {
		$file = __DIR__ . '/../' . $name;
		return $type === 'postgres'
			? $file . '.pg.sql'
			: $file . '.sql';
	}

	/**
	 * Tell the parser test engine to create a stub cu_changes table,
	 * or temporary pages won't save correctly during the test run.
	 * @param array &$tables
	 * @return bool
	 */
	public static function globalcheckUserParserTestTables( &$tables ) {
		$tables[] = 'gcu_changes';
		return true;
	}

	/**
	 * Add a link to Special:CheckUser and Special:CheckUserLog
	 * on Special:Contributions/<username> for
	 * privileged users.
	 * @param int $id User ID
	 * @param Title $nt User page title
	 * @param array &$links Tool links
	 * @param SpecialPage $sp Special page
	 */
	public static function globalcheckUserContributionsLinks(
		$id, Title $nt, array &$links, SpecialPage $sp
	) {
		$user = $sp->getUser();
		$linkRenderer = $sp->getLinkRenderer();
		if ( $user->isAllowed( 'globalcheckuser' ) ) {
			$links['checkuser'] = $linkRenderer->makeKnownLink(
				SpecialPage::getTitleFor( 'GlobalCheckUser' ),
				$sp->msg( 'globalcheckuser-contribs' )->text(),
				[],
				[ 'user' => $nt->getText() ]
			);
		}
		if ( $user->isAllowed( 'globalcheckuser-log' ) ) {
			$links['globalcheckuser-log'] = $linkRenderer->makeKnownLink(
				SpecialPage::getTitleFor( 'GlobalCheckUserLog' ),
				$sp->msg( 'globalcheckuser-contribs-log' )->text(),
				[],
				[
					'gcuSearchType' => 'target',
					'gcuSearch' => $nt->getText()
				]
			);
		}
	}

	/**
	 * Retroactively autoblocks the last IP used by the user (if it is a user)
	 * blocked by this Block.
	 *
	 * @param Block $block
	 * @param array &$blockIds
	 * @return bool
	 */
	public static function doRetroactiveAutoblock( Block $block, array &$blockIds ) {
		global $wgGlobalCheckUserWikiId;
		$dbr = wfGetDB( DB_REPLICA, $wiki = $wgGlobalCheckUserWikiId );

		$user = User::newFromName( (string)$block->getTarget(), false );
		if ( !$user->getId() ) {
			return true; // user in an IP?
		}

		$options = [ 'ORDER BY' => 'cuc_timestamp DESC' ];
		$options['LIMIT'] = 1; // just the last IP used

		$res = $dbr->select( 'gcu_changes',
			[ 'gcuc_ip' ],
			[ 'gcuc_user' => $user->getId() ],
			__METHOD__,
			$options
		);

		# Iterate through IPs used (this is just one or zero for now)
		foreach ( $res as $row ) {
			if ( $row->gcuc_ip ) {
				$id = $block->doAutoblock( $row->gcuc_ip );
				if ( $id ) {
					$blockIds[] = $id;
				}
			}
		}

		return false; // autoblock handled
	}

	public static function onUserMergeAccountFields( array &$updateFields ) {
		$updateFields[] = [ 'gcu_changes', 'gcuc_user', 'gcuc_user_text' ];
		$updateFields[] = [ 'gcu_log', 'gcul_user', 'gcul_user_text' ];
		$updateFields[] = [ 'gcu_log', 'gcul_target_id' ];

		return true;
	}

	/**
	 * For integration with the Renameuser extension.
	 *
	 * @param RenameuserSQL $renameUserSQL
	 * @return bool
	 */
	public static function onRenameUserSQL( RenameuserSQL $renameUserSQL ) {
		$renameUserSQL->tablesJob['gcu_changes'] = [
			RenameuserSQL::NAME_COL => 'gcuc_user_text',
			RenameuserSQL::UID_COL  => 'gcuc_user',
			RenameuserSQL::TIME_COL => 'gcuc_timestamp',
			'uniqueKey'    => 'gcuc_id'
		];

		$renameUserSQL->tables['gcu_log'] = [ 'gcul_user_text', 'gcul_user' ];

		return true;
	}
}
