<?php

class SpecialGlobalCheckUserLog extends SpecialPage {
	/**
	 * @var string $target
	 */
	protected $target;

	public function __construct() {
		parent::__construct( 'GlobalCheckUserLog', 'globalcheckuser-log' );
	}

	public function execute( $par ) {
		$this->setHeaders();
		$this->checkPermissions();

		// Blocked users are not allowed to run checkuser queries (bug T157883)
		$block = $this->getUser()->getBlock();
		if ( $block && $block->isSitewide() ) {
			throw new UserBlockedError( $block );
		}

		$out = $this->getOutput();
		$request = $this->getRequest();
		$this->target = trim( $request->getVal( 'cuSearch', $par ) );

		if ( $this->getUser()->isAllowed( 'globalcheckuser' ) ) {
			$subtitleLink = $this->getLinkRenderer()->makeKnownLink(
				SpecialPage::getTitleFor( 'GlobalCheckUser' ),
				$this->msg( 'globalcheckuser-showmain' )->text()
			);
			if ( !$this->target === false ) {
				$subtitleLink .= ' | ' . $this->getLinkRenderer()->makeKnownLink(
					SpecialPage::getTitleFor( 'GlobalCheckUser', $this->target ),
					$this->msg( 'globalcheckuser-check-this-user' )->text()
				);
			}
			$out->addSubtitle( $subtitleLink );
		}

		$type = $request->getVal( 'cuSearchType', 'target' );

		$this->displaySearchForm();

		// Default to all log entries - we'll add conditions below if a target was provided
		$searchConds = [];

		if ( $this->target !== '' ) {
			$searchConds = ( $type === 'initiator' )
				? $this->getPerformerSearchConds()
				: $this->getTargetSearchConds();
		}

		if ( $searchConds === null ) {
			// Invalid target was input so show an error message and stop from here
			$out->wrapWikiMsg( "<div class='errorbox'>\n$1\n</div>", 'checkuser-user-nonexistent' );
			return;
		}

		$pager = new GlobalCheckUserLogPager(
			$this->getContext(),
			[
				'queryConds' => $searchConds,
				'year' => $request->getInt( 'year' ),
				'month' => $request->getInt( 'month' ),
			]
		);

		$out->addHTML(
			$pager->getNavigationBar() .
			$pager->getBody() .
			$pager->getNavigationBar()
		);
	}

	/**
	 * Use an HTMLForm to create and output the search form used on this page.
	 */
	protected function displaySearchForm() {
		$request = $this->getRequest();
		$fields = [
			'target' => [
				'type' => 'user',
				// validation in execute() currently
				'exists' => false,
				'ipallowed' => true,
				'name' => 'gcuSearch',
				'size' => 40,
				'label-message' => 'globalcheckuser-log-search-target',
				'default' => $this->target,
			],
			'type' => [
				'type' => 'radio',
				'name' => 'gcuSearchType',
				'label-message' => 'globalcheckuser-log-search-type',
				'options-messages' => [
					'checkuser-search-target' => 'target',
					'checkuser-search-initiator' => 'initiator',
				],
				'flatlist' => true,
				'default' => 'target',
			],
			// @todo hack until HTMLFormField has a proper date selector
			'monthyear' => [
				'type' => 'info',
				'default' => Xml::dateMenu( $request->getInt( 'year' ), $request->getInt( 'month' ) ),
				'raw' => true,
			],
		];

		$form = HTMLForm::factory( 'table', $fields, $this->getContext() );
		$form->setMethod( 'get' )
			->setWrapperLegendMsg( 'globalcheckuser-search' )
			->setSubmitTextMsg( 'globalcheckuser-search-submit' )
			->prepareForm()
			->displayForm( false );
	}

	/**
	 * Get DB search conditions depending on the CU performer/initiator
	 * Use this only for searches by 'initiator' type
	 *
	 * @return array|null array if valid target, null if invalid
	 */
	protected function getPerformerSearchConds() {
		$initiator = User::newFromName( $this->target );
		if ( $initiator && $initiator->getId() ) {
			return [ 'gcul_user' => $initiator->getId() ];
		}
		return null;
	}

	/**
	 * Get DB search conditions according to the CU target given.
	 *
	 * @return array|null array if valid target, null if invalid target given
	 */
	protected function getTargetSearchConds() {
		list( $start, $end ) = IP::parseRange( $this->target );
		$conds = null;

		if ( $start !== false ) {
			$dbr = wfGetDB( DB_REPLICA );
			if ( $start === $end ) {
				// Single IP address
				$conds = [
					'gcul_target_hex = ' . $dbr->addQuotes( $start ) . ' OR ' .
					'(gcul_range_end >= ' . $dbr->addQuotes( $start ) . ' AND ' .
					'gcul_range_start <= ' . $dbr->addQuotes( $start ) . ')'
				];
			} else {
				// IP range
				$conds = [
					'(gcul_target_hex >= ' . $dbr->addQuotes( $start ) . ' AND ' .
					'gcul_target_hex <= ' . $dbr->addQuotes( $end ) . ') OR ' .
					'(gcul_range_end >= ' . $dbr->addQuotes( $start ) . ' AND ' .
					'gcul_range_start <= ' . $dbr->addQuotes( $end ) . ')'
				];
			}
		} else {
			$user = User::newFromName( $this->target );
			if ( $user && $user->getId() ) {
				// Registered user
				$conds = [
					'gcul_type' => [ 'userips', 'useredits' ],
					'gcul_target_id' => $user->getId(),
				];
			}
		}
		return $conds;
	}

	protected function getGroupName() {
		return 'changes';
	}
}
