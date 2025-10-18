// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Provider } from "../provider/Provider.sol";
import "../Config.sol";
import "./IUser.sol";


/**
 * @title User
 * @notice Implementation of user-facing bond operations
 * @dev This contract provides the EOA/smart wallet interface for bond creation and execution
 */
abstract contract User is IUser, Provider {

    constructor( address initial_admin, address eip1153_detector ) Provider( initial_admin, eip1153_detector ) { }


    function create_bond( bytes21 commitment_proof ) external  nonReentrant( BONDS_LOCK )
    {
        bool is_valid_commitment_proof  =  ( commitment_proof != bytes21(0) );
        if(  is_valid_commitment_proof == false  )  revert Invalid( COMMITMENT_PROOF_PARAM, 0 );

        TokenAmount[] memory stakes;  // Empty stakes.

        _create_bond_internal( commitment_proof, stakes );
    }

    function create_bond( bytes21 commitment_proof, TokenAmount[] memory stakes, uint256 creation_deadline ) external  nonReentrant( BONDS_LOCK )
    {
        bool is_valid_commitment_proof  =  ( commitment_proof != bytes21(0) );
        if(  is_valid_commitment_proof == false  )  revert Invalid( COMMITMENT_PROOF_PARAM, 0 );

        bool is_over_max_stakes  =   (  stakes.length > Config.MAX_STAKES_PER_BOND  );
        if(  is_over_max_stakes  )  revert TooManyStakes( stakes.length, Config.MAX_STAKES_PER_BOND );

        bool is_past_deadline   =   (  creation_deadline > 0  &&  block.timestamp >= creation_deadline  );  // Compare with "greater than or equals" to err on the safer side.
        if(  is_past_deadline  )  revert BondCreationPastDeadline( creation_deadline );

        _create_bond_internal( commitment_proof, stakes );
    }

    function execute_bond( uint64 bond_id, ExecutionData calldata execution_data ) external  nonReentrant( BONDS_LOCK )
    {
        _execute_bond_internal({
            bond_id:            bond_id,
            user:               msg.sender,
            execution_data:     execution_data
        });
    }

    function execute_bond_on_behalf_of_user( uint64 bond_id, ExecutionData calldata execution_data, address user, bytes calldata signature, bool is_eip1271 ) external  nonReentrant( BONDS_LOCK )
    {
        bool is_valid_signature  =  _is_valid_signature_for_bond_execution({
            bond_id:            bond_id,
            execution_data:     execution_data,
            user:               user,
            signature:          signature,
            is_eip1271:         is_eip1271
        });
        if(  is_valid_signature == false  )  revert InvalidSignature( bond_id );

        _execute_bond_internal({
            bond_id:            bond_id,
            user:               user,
            execution_data:     execution_data
        });
    }

    
    function __OFF_CHAIN__get_bond( uint64 bond_id ) external view returns ( Bond memory bond, TokenAmount[] memory stakes )
    {
        bond    =   _get_bond_internal( bond_id );
        stakes  =   _load_bond_stakes( bond_id, bond.count_of_staked_tokens );
    }

    function __OFF_CHAIN__calculate_commitment_proof( address user, ExecutionData calldata execution_data ) external view returns ( bytes21 )
    {
        return _calculate_commitment_proof( user, execution_data );
    }
}