// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import "../IBondRoute.sol";
import "./IBondRouteProtected.sol";
import { TokenTransferFailed, InsufficientFunds, PushedFundsOverflow } from "../provider/IProvider.sol";


/**
 * @title BondRouteProtected
 * @notice Abstract contract providing BondRoute MEV protection functionality
 * @dev Contracts should inherit from this and implement `BondRoute_get_execution_constraints`
 */
abstract contract BondRouteProtected is IBondRouteProtected {

    // *DEPLOYMENT_STRATEGY* - Hardcoded address enables deterministic cross-chain deployments.
    //                        BondRoute will be deployed to the same vanity-mined address on all chains
    //                        using identical bytecode. This allows Protected contracts to have identical
    //                        bytecode and thus deploy to the same addresses across all chains via CREATE2.
    //                        Deployment flow: 1) Deploy BondRoute to vanity address, 2) Update this constant,
    //                        3) Deploy Protected contracts with identical bytecode everywhere.
    IBondRoute constant BondRoute  =  IBondRoute(0x0000000000000000000000000000000000000000);  // TODO* Update after BondRoute deployment
    
    
    // ═══════════════════════════════════════════════════════════════════════════════
    //                              SECURITY: TOKEN INTEGRATION CONFLICT
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /**
     * @dev Intentional conflict to prevent unsafe token + BondRouteProtected implementation
     * @dev If you see this compilation error, you're implementing a token standard alongside BondRouteProtected
     * @dev This is UNSAFE without proper security measures because delegatecall preserves msg.sender = BondRoute
     * @dev 
     * @dev TO FIX THIS ERROR:
     * @dev 1. Override this function to delegate to your token implementation
     * @dev 2. Override BondRoute_entry_point() with selector filtering to prevent fund theft
     * @dev 
     * @dev EXAMPLE SAFE OVERRIDE:
     * @dev function balanceOf(address account) public view override(BondRouteProtected, ERC20) returns (uint256) {
     * @dev     return ERC20.balanceOf(account);
     * @dev }
     * @dev function BondRoute_entry_point(bytes calldata target_calldata) external override onlyBondRoute {
     * @dev     bytes4 selector = bytes4(target_calldata);
     * @dev     require(selector != IERC20.transfer.selector, "Forbidden: transfer");
     * @dev     require(selector != IERC20.transferFrom.selector, "Forbidden: transferFrom");
     * @dev     super.BondRoute_entry_point(target_calldata);
     * @dev }
     * @dev 
     * @dev See: https://docs.bondroute.xyz/security/token-integration
     */
    function balanceOf( address ) external pure virtual returns ( uint256 )
    {
        revert( "SECURITY: Token + BondRouteProtected requires overriding BondRoute_entry_point() with selector filtering" );
    }


    modifier onlyBondRoute( )
    {
        _onlyBondRoute( );
        _;
    }

    function _onlyBondRoute( ) private view
    {
        if(  msg.sender != address(BondRoute)  )  revert Unauthorized( msg.sender );
    }

    
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 _BONDROUTEPROTECTED_MAGIC_SIGNATURE )
    {
        return BONDROUTEPROTECTED_MAGIC_SIGNATURE;
    }


    // ═══════════════════════════════════════════════════════════════════════════════
    //                              BONDROUTE ENTRY POINT
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Entry point for BondRoute calls with MEV protection
     * @param target_calldata_with_appended_context The target function calldata with encoded context appended
     * @dev Called by BondRoute contract only. Validates sender and delegates to target function.
     *      Context format: abi.encode(packed_user_and_commit_info, staked_token, staked_amount)
     */
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external virtual  onlyBondRoute
    {
        // *RATIONALE*  -  We use delegatecall instead of regular call for crucial developer experience and security reasons:
        //
        //                              1. PRESERVES CALL CONTEXT SEMANTICS:
        //                                 - Functions called through BondRoute: msg.sender = BondRoute
        //                                 - Functions called directly by users: msg.sender = user  
        //                                 - Functions called by contract self-calls: msg.sender = address(this)
        //                                 This enables developers to use different access control for each context with clear semantics.
        //
        //                              2. PROTECTS SELF-CALL GUARDS:
        //                                 Many contracts use `require(msg.sender == address(this))` to ensure functions
        //                                 are only callable via try/catch self-calls for graceful error handling.
        //                                 Regular call would break this by making msg.sender = address(this) during bond execution,
        //                                 accidentally exposing internal functions that should only be self-callable.
        //
        //                              3. MAINTAINS SECURITY BOUNDARIES:
        //                                 Developers can safely distinguish between:
        //                                 - onlyBondRoute functions (bond-protected operations)  
        //                                 - onlyOwner functions (admin operations, fails if called through bonds)
        //                                 - self-call functions (internal operations with graceful error handling)
        //
        // *SECURITY TRADEOFF*        -  However, delegatecall preserves msg.sender = BondRoute throughout the call stack.
        //                              This creates a critical vulnerability if the integrator contract ALSO implements
        //                              token standards (ERC20, ERC721, etc.) because:
        //                              
        //                              ATTACK: Malicious bond calls token functions with msg.sender = BondRoute
        //                              → token.transfer(attacker, huge_amount) 
        //                              → Executes as if BondRoute is calling transfer()
        //                              → Can steal BondRoute's token holdings (user stakes)
        //
        //                              MITIGATION: We provide balanceOf() conflict detection to prevent accidental
        //                              unsafe token integration. Developers implementing tokens MUST override 
        //                              BondRoute_entry_point() with function selector filtering.
        //
        // *DESIGN DECISION*          -  We prioritize excellent DX for 99% of use cases (non-token contracts) while
        //                              requiring explicit security measures for the 1% edge case (token contracts).
        //                              This prevents degrading the developer experience for common integrations
        //                              (DEXes, DAOs, games, prediction markets) to solve an uncommon edge case.
        //
        //                              Alternative approaches considered:
        //                              - Regular call: Breaks self-call semantics and access control patterns
        //                              - Selector blacklists: Cannot anticipate all dangerous non-standard functions
        //                              - Vault pattern: Adds gas costs and complexity for all users
        ( bool success, bytes memory delegatecall_output )  =  address(this).delegatecall( target_calldata_with_appended_context );
        
        if( success == false )
        {
            // *SECURITY*  -  Propagate the exact error even if `delegatecall_output` is empty as that could be an OOG attack that will be handled upstream by BondRoute.
            assembly ("memory-safe") {
                revert( add( delegatecall_output, 0x20 ), mload( delegatecall_output ) )
            }
        }
    }


    /**
     * @notice Initialize BondRoute context and load available funding information  
     * @return context Full context including user, timing, staking, and available funding
     * @dev This is the standard initialization function for most use cases.
     *      Provides access to user info, timing, staking, and funding operations.
     *      For gas optimization in non-financial operations, use `BondRoute_initialize_without_funds()`.
     */
    function BondRoute_initialize( ) internal view returns ( BondRouteContext memory context )
    {
        context             =  _extract_context_from_calldata( );
        context.fundings    =  BondRoute.get_available_funds( );
        
        BondRoute_validate( context );

        return context;
    }



    /**
     * @notice Initialize BondRoute context without loading funding information
     * @return context Basic context (user, timing, staking) - no funding data loaded
     * @dev Use for functions that don't need funding operations (voting, messaging, etc.)
     *      GAS OPTIMIZATION: This saves significant gas compared to `BondRoute_initialize()`
     *      by skipping the external call to `get_available_funds()` and array allocation.
     *      Use this whenever possible for non-financial operations.
     */
    function BondRoute_initialize_without_funds( ) internal view returns ( BondRouteContext memory context )
    {
        context  =  _extract_context_from_calldata( );
        
        BondRoute_validate( context );

        return context;
    }


    /**
     * @dev Extract context data from appended calldata (shared logic)
     */
    function _extract_context_from_calldata( ) private pure returns ( BondRouteContext memory context )
    {
        // Extract the appended context from `msg.data`.
        // Context format: `abi.encode(packed_user_and_commit_info, staked_token, staked_amount)`
        // This is 96 bytes (3 words of 32 bytes each) to the end of `msg.data`.
        if(  msg.data.length < 96  )  revert( "Invalid context data" );
        
        // Decode the appended context from the last 96 bytes.
        bytes calldata encoded_context  =  msg.data[ msg.data.length - 96 : ];
        
        uint256 packed_user_and_commit_info;  // (user << 80) | (timestamp << 40) | block_number
        address staked_token;
        uint256 staked_amount;
        
        assembly {
            packed_user_and_commit_info     :=  calldataload( add( encoded_context.offset, 0x00 ) )
            staked_token                    :=  calldataload( add( encoded_context.offset, 0x20 ) )
            staked_amount                   :=  calldataload( add( encoded_context.offset, 0x40 ) )
        }

        // forge-lint: disable-start(unsafe-typecast)
        // Created with:
        // uint256 packed_user_and_commit_info  =  ( uint256(uint160(user)) << 80 ) | ( uint256(bond.created_at_timestamp) << 40 ) | uint256(bond.created_at_block_number);
        context.user                        =  address(uint160(packed_user_and_commit_info >> 80));
        context.commit_time                 =  uint40(( packed_user_and_commit_info >> 40 ) & 0xffffffffff);
        context.commit_block                =  uint40(packed_user_and_commit_info & 0xffffffffff);
        // forge-lint: disable-end(unsafe-typecast)

        context.stake.token                 =  IERC20(staked_token);
        context.stake.amount                =  staked_amount;
        
        // *Note*  -  `context.fundings` is empty by default and may be loaded later on.
    }


    /**
     * @notice Get available funds for the current execution
     * @return fundings Array of available funds that can be pulled
     * @dev Reverts with `Unauthorized` if called outside of bond execution context
     */
    function BondRoute_get_available_funds( ) internal view returns ( TokenAmount[] memory fundings )
    {
        return BondRoute.get_available_funds( );
    }


    /**
     * @notice Get available funds for a specific token during current execution
     * @param token The token address to check available funds for
     * @return amount The total amount of the specified token available for pulling
     * @dev Returns 0 if no funds available for the token. Reverts with `Unauthorized` if called outside of bond execution context
     */
    function BondRoute_get_available_amount_for_token( IERC20 token ) internal view returns ( uint256 amount )
    {
        return BondRoute.get_available_amount_for_token( token );
    }


    /**
     * @notice Push tokens to BondRoute funding
     * @param token Address of token to push
     * @param amount Amount of tokens to push
     * @dev Detects overflow manipulation attacks and converts to PossiblyBondPicking
     */
    function BondRoute_push( IERC20 token, uint256 amount ) internal
    {
        // *NOTE*  -  Always sets infinite approval to prevent multiple calls from overwriting the previous push since it could brick the transaction and the user's stake.
        token.approve( address(BondRoute), type(uint256).max );

        try BondRoute.push_funds( token, amount ) { }
        catch( bytes memory _error )
        {
            // Check for PushedFundsOverflow which could be manipulated by attacker
            if(  _error.length >= 4  )
            {
                // forge-lint: disable-next-line(unsafe-typecast)  -  Safe bc checked length is >= 4.
                bytes4 error_selector  =  bytes4(_error);
                if(  error_selector == PushedFundsOverflow.selector  )
                {
                    revert PossiblyBondPicking( "Push overflow manipulation" );
                }
            }
            
            // Re-throw other errors unchanged (including OOG which will be caught by BondRoute core)
            assembly ("memory-safe") {
                revert( add( _error, 0x20 ), mload( _error ) )
            }
        }
    }


    /**
     * @notice Pull tokens from BondRoute funding
     * @param token Address of token to pull
     * @param amount Exact amount of tokens to pull
     * @return net_amount The calculated net amount after BondRoute's 0.01% fee deduction
     * @dev Reverts if funds were not approved to BondRoute
     *      Detects transfer manipulation attacks and converts to PossiblyBondPicking
     */
    function BondRoute_pull( IERC20 token, uint256 amount ) internal returns ( uint256 net_amount )
    {
        try BondRoute.pull_funds( token, amount ) returns ( uint256 _net_amount ) {
            return _net_amount;
        }
        catch( bytes memory _error )
        {
            // Check for specific funding-related errors that could be manipulated
            if(  _error.length >= 4  )
            {
                // forge-lint: disable-next-line(unsafe-typecast)  -  Safe bc checked length is >= 4.
                bytes4 error_selector  =  bytes4(_error);
                if(  error_selector == TokenTransferFailed.selector  ||  error_selector == InsufficientFunds.selector  )
                {
                    revert PossiblyBondPicking( TRANSFER_FAILED );
                }
            }
            
            // Re-throw other errors unchanged (including OOG which will be caught by BondRoute core)
            assembly ("memory-safe") {
                revert( add( _error, 0x20 ), mload( _error ) )
            }
        }
    }


    /**
     * @notice Send tokens from BondRoute funding to beneficiary
     * @param token Address of token to send
     * @param amount Exact amount of tokens to send
     * @param beneficiary Address to receive the tokens
     * @return net_amount The calculated net amount after BondRoute's 0.01% fee deduction
     * @dev Reverts if funds were not approved to BondRoute
     *      Detects transfer manipulation attacks and converts to PossiblyBondPicking
     */
    function BondRoute_send( IERC20 token, uint256 amount, address beneficiary ) internal returns ( uint256 net_amount )
    {
        try BondRoute.send_funds( token, amount, beneficiary ) returns ( uint256 _net_amount ) {
            return _net_amount;
        }
        catch( bytes memory _error )
        {
            // Check for specific funding-related errors that could be manipulated
            if(  _error.length >= 4  )
            {
                // forge-lint: disable-next-line(unsafe-typecast)  -  Safe bc checked length is >= 4.
                bytes4 error_selector  =  bytes4(_error);
                if(  error_selector == TokenTransferFailed.selector  ||  error_selector == InsufficientFunds.selector  )
                {
                    revert PossiblyBondPicking( TRANSFER_FAILED );
                }
            }
            
            // Re-throw other errors unchanged (including OOG which will be caught by BondRoute core)
            assembly ("memory-safe") {
                revert( add( _error, 0x20 ), mload( _error ) )
            }
        }
    }


    /**
     * @notice Validate BondRoute execution context against your protocol's rules
     * @param context The BondRoute context to validate
     * @dev Override this function to define your protocol's security requirements.
     *      This is called automatically by BondRoute_initialize() and BondRoute_initialize_without_funds().
     *      Default implementation calls `BondRoute_get_execution_constraints` for validation.
     */
    function BondRoute_validate( BondRouteContext memory context ) internal view virtual
    {
        ExecutionConstraints memory constraints  =  BondRoute_get_execution_constraints({
            target_calldata:            msg.data,
            preferred_stake_token:      context.stake.token,
            preferred_fundings:         context.fundings
        });

        // Bond creation absolute timing validation.
        if(  constraints.min_bond_creation_time > 0  &&  context.commit_time < constraints.min_bond_creation_time  )
        {
            revert BondCreatedTooEarly({
                created_at:             context.commit_time,
                min_creation_time:      constraints.min_bond_creation_time
            });
        }
        if(  constraints.max_bond_creation_time > 0  &&  context.commit_time > constraints.max_bond_creation_time  )
        {
            revert BondCreatedTooLate({
                created_at:             context.commit_time,
                max_creation_time:      constraints.max_bond_creation_time
            });
        }
        
        // Relative timing validation (MEV protection).
        uint execution_delay  =  block.timestamp - context.commit_time;
        if(  constraints.min_execution_delay > 0  &&  execution_delay < constraints.min_execution_delay  )
        {
            revert ExecutionTooSoon({
                delay:                  execution_delay,
                min_delay:              constraints.min_execution_delay
            });
        }
        if(  constraints.max_execution_delay > 0  &&  execution_delay > constraints.max_execution_delay  )
        {
            revert ExecutionTooLate({
                delay:                  execution_delay,
                max_delay:              constraints.max_execution_delay
            });
        }
        
        // Bond execution absolute timing validation.
        if(  constraints.min_bond_execution_time > 0  &&  block.timestamp < constraints.min_bond_execution_time  )
        {
            revert BeforeExecutionWindow({
                current_time:           block.timestamp,
                min_execution_time:     constraints.min_bond_execution_time
            });
        }
        if(  constraints.max_bond_execution_time > 0  &&  block.timestamp > constraints.max_bond_execution_time  )
        {
            revert AfterExecutionWindow({
                current_time:           block.timestamp,
                max_execution_time:     constraints.max_bond_execution_time
            });
        }

        // Staking validation.
        if(  address(constraints.stake.token) != address(0)  &&  context.stake.token != constraints.stake.token  )
        {
            revert InvalidStakeToken({
                provided:               address(context.stake.token),
                required:               address(constraints.stake.token)
            });
        }
        if(  context.stake.amount < constraints.stake.amount  )
        {
            revert InsufficientStake({
                provided:               context.stake.amount,
                required:               constraints.stake.amount
            });
        }
    }
    

    /**
     * @dev Implementers must override this function to define their BondRoute requirements
     */
    function BondRoute_get_execution_constraints( bytes calldata target_calldata, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings ) public view virtual override returns ( ExecutionConstraints memory execution_constraints );
    

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              SAFE EXTERNAL CALL UTILITIES
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Utility function to check if a caught error indicates possibly bond-picking
     * @param call_output The error bytes from a failed external call (from catch block)
     * @dev Call this in catch blocks to detect and prevent out-of-gas and bond-picking attacks
     */
    function BondRoute_revert_if_possibly_bond_picking( bytes memory call_output ) internal pure
    {
        // Check for out-of-gas attacks.
        if(  call_output.length == 0  )  revert PossiblyBondPicking( POSSIBLY_OUT_OF_GAS );
        
        // Check for PossiblyBondPicking error propagation
        if(  call_output.length >= 4  )
        {
            // forge-lint: disable-next-line(unsafe-typecast)  -  Safe bc checked length is >= 4.
            bytes4 error_selector  =  bytes4(call_output);
            if(  error_selector == PossiblyBondPicking.selector  )
            {
                // Propagate the original error unchanged
                assembly ("memory-safe") {
                    revert( add( call_output, 0x20 ), mload( call_output ) )
                }
            }
        }
    }
}
