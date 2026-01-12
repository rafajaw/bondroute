// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol, FundingTransfer } from "@test/mocks/MockProtocol.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title FuzzTest
 * @notice Property-based fuzz testing for BondRoute invariants
 * @dev Only tests meaningful properties - not keccak256 behavior
 */
contract FuzzTest is Test {

    BondRoute public bondRoute;
    MockERC20 public usdc;
    MockProtocol public mock_protocol;

    address public constant COLLECTOR  =  address(uint160(uint256(keccak256("COLLECTOR"))));
    address public constant USER       =  address(0x1111);
    address public constant RECIPIENT  =  address(0x2222);

    function setUp() public {
        bondRoute         =  new BondRoute( COLLECTOR );
        usdc              =  new MockERC20( "USDC", "USDC" );
        mock_protocol     =  new MockProtocol();

        usdc.mint( USER, type(uint128).max );
        vm.deal( USER, type(uint128).max );

        vm.prank( USER );
        usdc.approve( address(bondRoute), type(uint256).max );
    }


    // ━━━━  STAKE INVARIANT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// @notice Stake is always refunded on successful execution
    function testFuzz_execute_bond_stake_always_refunded( uint256 stake_amount ) public {
        stake_amount  =  bound( stake_amount, 1e6, 1000000e6 );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: stake_amount });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt:      stake_amount,  // Use stake_amount as salt for uniqueness
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake );

        assertEq( usdc.balanceOf( USER ), user_balance_before - stake_amount, "Stake should be taken" );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        bondRoute.execute_bond( execution_data );

        assertEq( usdc.balanceOf( USER ), user_balance_before, "Stake should be fully refunded" );
    }


    // ━━━━  FUNDING CONSERVATION INVARIANT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// @notice Fundings are conserved - pulled from user, sent to recipient
    function testFuzz_execute_bond_funding_conservation( uint256 amount ) public {
        amount  =  bound( amount, 100e6, 10000e6 );

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: amount });

        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        FundingTransfer[] memory transfers  =  new FundingTransfer[](1);
        transfers[ 0 ]  =  FundingTransfer({
            to:          RECIPIENT,
            token:       usdc,
            amount:      amount
        });
        mock_protocol.set_funding_transfers( transfers );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  fundings,
            stake:     stake,
            salt:      amount,  // Use amount as salt for uniqueness
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bondRoute.create_bond{ value: 1 ether }( commitment_hash, stake );

        uint256 user_usdc_before  =  usdc.balanceOf( USER );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = bondRoute.execute_bond( execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Execution should succeed" );

        assertEq( usdc.balanceOf( USER ), user_usdc_before - amount, "User should pay funding" );
        assertEq( usdc.balanceOf( RECIPIENT ), amount, "Recipient should receive funding" );
    }


    // ━━━━  LIQUIDATION BOUNDARY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// @notice Liquidation only possible after MAX_BOND_LIFETIME
    function testFuzz_liquidate_only_after_expiration( uint256 time_warp ) public {
        time_warp  =  bound( time_warp, 0, 365 days );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt:      time_warp,  // Use time_warp as salt for uniqueness
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.warp( block.timestamp + time_warp );

        if(  time_warp < MAX_BOND_LIFETIME  )
        {
            vm.prank( COLLECTOR );
            vm.expectRevert();
            bondRoute.liquidate_expired_bonds( commitment_hashes, stakes, COLLECTOR );
        }
        else
        {
            vm.prank( COLLECTOR );
            bondRoute.liquidate_expired_bonds( commitment_hashes, stakes, COLLECTOR );

            assertEq( usdc.balanceOf( COLLECTOR ), 1000e6, "Collector should receive liquidated stake" );
        }
    }


    // ━━━━  AIRDROP ACCOUNTING  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// @notice Airdrops accumulate correctly and are claimable
    function testFuzz_airdrop_accumulation( uint8 airdrop_count ) public {
        airdrop_count  =  uint8(bound( airdrop_count, 1, 10 ));

        uint256 total_airdrops  =  0;

        for(  uint256 i = 0  ;  i < airdrop_count  ;  i++  )
        {
            uint256 airdrop_amount  =  (i + 1) * 1e18;
            total_airdrops  +=  airdrop_amount;

            vm.prank( USER );
            bondRoute.airdrop{ value: airdrop_amount }( IERC20(address(0)), airdrop_amount, "fuzz test airdrop" );
        }

        assertGe( address(bondRoute).balance, total_airdrops - airdrop_count, "Total airdrops should accumulate" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  IERC20(address(0));

        uint256 collector_before  =  COLLECTOR.balance;

        vm.prank( COLLECTOR );
        bondRoute.claim_airdrops( tokens, COLLECTOR );

        assertGe( COLLECTOR.balance - collector_before, total_airdrops - airdrop_count, "Collector should receive airdrops" );
    }
}
