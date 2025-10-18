// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Core } from "../core/Core.sol";
import { Config } from "../Config.sol";
import { Bond } from "../user/IUser.sol";
import { TokenAmount } from "../integrations/IBondRouteProtected.sol";
import "./IAdmin.sol";


abstract contract Admin is IAdmin, Core {

    constructor( address initial_admin, address eip1153_detector ) Core( eip1153_detector )
    {
        if(  initial_admin == address(0)  )  revert( ADMIN_ZERO_ADDRESS );
        
        _admin              =  initial_admin;
        _protocol_treasury  =  initial_admin;  // By default set the protocol treasury as the initial admin
        
        emit AdminChanged({
            new_admin:          initial_admin,
            old_admin:          address(0)
        });
        emit ProtocolTreasuryChanged({
            new_treasury:       initial_admin,
            old_treasury:       address(0)
        });
    }

    modifier onlyAdmin( )
    {
        _onlyAdmin( );

        _;
    }

    function _onlyAdmin( ) private view
    {
        if(  msg.sender != _admin  )  revert Forbidden( ADMIN_ACCESS_REQUIRED );
    }

    
    function appoint_new_admin( address new_admin ) external  onlyAdmin
    {
        if(  new_admin == address(0)  )  revert Forbidden( ADMIN_ZERO_ADDRESS );

        _pending_new_admin  =  new_admin;
        
        emit AdminAppointed({
            pending_admin:      new_admin,
            current_admin:      msg.sender
        });
    }
    
    function accept_admin_appointment( ) external
    {
        if(  msg.sender != _pending_new_admin  )  revert Forbidden( APPOINTED_ADMIN_REQUIRED );

        address old_admin   =  _admin;
        _admin              =  _pending_new_admin;
        _pending_new_admin  =  address(0);
        
        emit AdminChanged({
            new_admin:      _admin,
            old_admin:      old_admin
        });
    }

    function set_protocol_treasury( address new_treasury ) external  onlyAdmin
    {
        if(  new_treasury == address(0)  )  revert Forbidden( INVALID_ADDRESS );

        address old_treasury  =  _protocol_treasury;
        _protocol_treasury  =  new_treasury;
        
        emit ProtocolTreasuryChanged({
            new_treasury:   new_treasury,
            old_treasury:   old_treasury
        });
    }

    function liquidate_defaulted_bonds( uint64[] calldata bond_ids, address beneficiary_address ) external  onlyAdmin  nonReentrant( BONDS_LOCK )
    {
        if(  bond_ids.length == 0  )                revert Forbidden( EMPTY_ARRAY );
        if(  beneficiary_address == address(0)  )   revert Forbidden( INVALID_ADDRESS );

        uint64[] memory liquidated_bond_ids     =   new uint64[]( bond_ids.length );     // Allocate max possible size first.
        uint256 k                               =   0;                                   // The iterator for actual liquidated bonds.

        for(  uint i = 0  ;  i < bond_ids.length  ;  i++  )
        {
            uint64 bond_id      =   bond_ids[ i ];
            Bond memory bond    =   _get_bond_internal( bond_id );

            uint256 bond_expiry_timestamp  =  bond.created_at_timestamp + Config.HARD_CAP_EXECUTION_WINDOW;
            bool did_bond_expire  =  ( block.timestamp > bond_expiry_timestamp );
            if(  did_bond_expire == false  )  continue;
            
            unchecked  // *GAS SAVING*  -  Safe bc `k++` is bounded by `bond_ids` length.
            {   
                liquidated_bond_ids[ k++ ]  =  bond_id;
            }

            if(  bond.count_of_staked_tokens == 0  )
            {
                delete _bonds[ bond_id ];  // Delete expired bond for state unbloat.
            }
            else
            {
                TokenAmount[] memory stakes  =  _load_bond_stakes( bond_id, bond.count_of_staked_tokens );
                _transfer_stakes_to_user_and_delete_bond( bond_id, beneficiary_address, stakes );
            }
        }
        
        assembly ("memory-safe") {
            mstore( liquidated_bond_ids, k )  // Trim down `liquidated_bond_ids` array to actual liquidated bond count.
        }
        
        emit BondsLiquidated({
            liquidated_bond_ids:    liquidated_bond_ids,
            beneficiary_address:    beneficiary_address
        });
    }

}
