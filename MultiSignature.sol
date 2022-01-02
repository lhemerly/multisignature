// MultiSignature Access Control
// SPDX-License-Identifier: MIT
// Created by: Luiz Hemerly @Dreadnaugh

pragma solidity 0.8.11;

import "@openzeppelin/contracts/access/AccessControl.sol";

// An extension of Access Control to include multi owner approval to execute key actions
// in this first version every signatorie has the same privileges and after collecting
// the minimum signatures necessary will give a ticket to any admins to execute the given
// action.
// TODO: Specify the inputs of the function to be executed

contract MultiSignature is AccessControl {

    // @dev action to kick a signatory. Useful for hacked wallets.
    bytes32 public constant VOTE_KICK = keccak256("VOTE_KICK");
    // @dev action to grant roles
    bytes32 public constant GRANT_ROLE = keccak256("GRANT_ROLE");
    // @dev action to revoke roles
    bytes32 public constant REVOKE_ROLE = keccak256("REVOKE_ROLE");

    // @dev minimumSignatures to pass a ticket. Should be set at constructor
    uint minimumSignatures;
    // @dev number of signatures per action
    mapping (bytes32=>uint) public signatures;
    // @dev each admin has one signature at a time only.
    mapping (address=>bool) public hasSignature;
    // @dev which action the signatory is supporting.
    mapping (address=>bytes32) public signatorySupport;

    // @dev modifier to check and consume ticket for a given action
    // not every action should need a ticket, it is usually restricted to key
    // functions like changing roles and withdraw funds
    modifier needTicket(bytes32 action){
        _checkTicket(action);
        _consumeTicket(action);
        _;
    }

    // @dev checking if there is enough tickets for given action
    // reverts with actual number of signatures and number of needed signatures
    function _checkTicket(bytes32 action) private view{
        require(signatures[action] >= minimumSignatures, 
                string(abi.encodePacked("MultiSignature: Action needs ", minimumSignatures,
                                        " signatures. Current signatures ", signatures[action])));
    }

    // @dev consumes signatures
    function _consumeTicket(bytes32 action) private {
        signatures[action] = 0;
        signatorySupport[msg.sender] = 0x00;
    }

    // @dev All signatories are admins with the same privilege and only one vote at a time
    function signAction(bytes32 action) external onlyRole(0x00) {
        require(hasSignature[msg.sender], "MultiSignature: No signatures left in this wallet.");
        hasSignature[msg.sender] = false;
        signatorySupport[msg.sender] = action;
        signatures[action] += 1;
    }

    // @dev unsign supported action and recover vote power
    function unsignAction() external onlyRole(0x00) {
        require(!hasSignature[msg.sender], "MultiSignature: No signatures to unsign in this wallet.");
        hasSignature[msg.sender] = true;
        signatures[signatorySupport[msg.sender]] -= 1;
        signatorySupport[msg.sender] = 0x00;
    }

    // @dev vote kick function in case of a signatory hacked wallet, for example
    function voteKick(address toKick) external onlyRole(0x00) needTicket(VOTE_KICK) {
        _revokeRole(0x00, toKick);
    }

    // @dev overrides to require ticket to change roles
    function grantRole(bytes32 role, address account)
    public virtual override onlyRole(getRoleAdmin(role)) needTicket(GRANT_ROLE) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account)
    public virtual override onlyRole(getRoleAdmin(role)) needTicket(REVOKE_ROLE) {
        _revokeRole(role, account);
    }

}
