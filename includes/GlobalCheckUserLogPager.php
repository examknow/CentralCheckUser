<?php

use Wikimedia\Rdbms\IResultWrapper;

class CheckUserLogPager extends ReverseChronologicalPager {
	/**
	 * @var array $searchConds
	 */
	protected $searchConds;

	/**
	 * @param IContextSource $context
	 * @param array $conds Should include 'queryConds', 'year', and 'month' keys
	 */
	public function __construct( IContextSource $context, array $conds ) {
		parent::__construct( $context );
		$this->searchConds = $conds['queryConds'];
		// getDateCond() actually *sets* the timestamp offset..
		$this->getDateCond( $conds['year'], $conds['month'] );
	}

	public function formatRow( $row ) {
		$user = Linker::userLink( $row->gcul_user, $row->user_name );

		if ( $row->cul_type == 'userips' || $row->cul_type == 'useredits' ) {
			$target = Linker::userLink( $row->gcul_target_id, $row->cul_target_text ) .
					Linker::userToolLinks( $row->gcul_target_id, $row->cul_target_text );
		} else {
			$target = $row->cul_target_text;
		}

		// Give grep a chance to find the usages:
		// checkuser-log-entry-userips, checkuser-log-entry-ipedits,
		// checkuser-log-entry-ipusers, checkuser-log-entry-ipedits-xff
		// checkuser-log-entry-ipusers-xff, checkuser-log-entry-useredits
		return '<li>' .
			$this->msg(
				'globalcheckuser-log-entry-' . $row->cul_type,
				$user,
				$target,
				$this->getLanguage()->timeanddate( wfTimestamp( TS_MW, $row->gcul_timestamp ), true ),
				$this->getLanguage()->date( wfTimestamp( TS_MW, $row->gcul_timestamp ), true ),
				$this->getLanguage()->time( wfTimestamp( TS_MW, $row->gcul_timestamp ), true )
			)->text() .
			Linker::commentBlock( $row->gcul_reason ) .
			'</li>';
	}

	/**
	 * @return string
	 */
	public function getStartBody() {
		if ( $this->getNumRows() ) {
			return '<ul>';
		} else {
			return '';
		}
	}

	/**
	 * @return string
	 */
	public function getEndBody() {
		if ( $this->getNumRows() ) {
			return '</ul>';
		} else {
			return '';
		}
	}

	/**
	 * @return string
	 */
	public function getEmptyBody() {
		return '<p>' . $this->msg( 'globalcheckuser-empty' )->escaped() . '</p>';
	}

	public function getQueryInfo() {
		return [
			'tables' => [ 'gcu_log', 'user' ],
			'fields' => $this->selectFields(),
			'conds' => array_merge( $this->searchConds, [ 'user_id = gcul_user' ] )
		];
	}

	public function getIndexField() {
		return 'gcul_timestamp';
	}

	public function selectFields() {
		return [
			'gcul_id', 'gcul_timestamp', 'gcul_user', 'gcul_reason', 'gcul_type',
			'gcul_target_id', 'gcul_target_text', 'user_name'
		];
	}

	/**
	 * Do a batch query for links' existence and add it to LinkCache
	 *
	 * @param IResultWrapper $result
	 */
	protected function preprocessResults( $result ) {
		if ( $this->getNumRows() === 0 ) {
			return;
		}

		$lb = new LinkBatch;
		$lb->setCaller( __METHOD__ );
		foreach ( $result as $row ) {
			$lb->add( NS_USER, $row->user_name ); // Performer
			if ( $row->gcul_type == 'userips' || $row->gcul_type == 'useredits' ) {
				$lb->add( NS_USER, $row->gcul_target_text );
				$lb->add( NS_USER_TALK, $row->gcul_target_text );
			}
		}
		$lb->execute();
		$result->seek( 0 );
	}
}
