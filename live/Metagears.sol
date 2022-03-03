// **                                                               
//             __  ___    __       ___           __      
//            /  |/  /__ / /____ _/ _ )_______ _///_ __ ___
//   ________/ /|_/ / -_/ __/ _ `/ _  / __/ _ `/ / \/ /__ /_____
//  /_________/  /_/\__/\__/\_,_/____/_/  \_,_/_/_//_/_________/
// ////////////////////////////////////////////////////////////
// **                
// SPDX-License-Identifier: GPL-3.0
// Contract:    MetaGears
// Project:     MetaBrainz.io
// Author:      LnrCdr, https://github.com/unameit10000000
// Date:        26-1-2022
// **

pragma solidity ^0.8.7;
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";


library NFTRestriction{
    enum LockType{ Global, Admins, Users }
    function outOfBounds(uint256 n, uint256 upperBound) internal pure returns(bool) {
        return n>0 && n<upperBound+1;
    }
}

interface NFTBase{
    struct NFT {
        uint256 id;
        string uri;
        uint256 max;
        uint256 cur;
        uint256 limit;
        uint256 price;
        mapping(NFTRestriction.LockType => bool) lock;
        bool isset;
    }

    modifier reserved(NFT storage reserve, bool onReserved){
        if(!onReserved){
            require(!reserve.isset, "Token already reserved!");_;
        }
        else{
            require(reserve.isset, "Token not yet reserved!");_;
        }
    }

    modifier restrictByMax(NFT storage reserve, uint256 amount){
        require(NFTRestriction.outOfBounds(reserve.cur+amount, reserve.max), "Action exceeds token max!");
        _;
    }

    modifier restrictByLimit(NFT storage reserve, uint256 amount){
        require(NFTRestriction.outOfBounds(reserve.cur+amount, reserve.limit), "Action exceeds token limit!");
        _;
    }

    modifier mintLock(NFT storage reserve, uint8 lockType){
        require(!reserve.lock[NFTRestriction.LockType(lockType)], "Locked from minting!");
        _;
    }

    modifier validateFees(NFT storage reserve, uint256 amount){
        require(msg.value >= reserve.price * amount, "Not enough fees provided!");
        _;
    }
}

contract MetaGears is 
    ERC1155, AccessControl, 
    Pausable, ERC1155Burnable, 
    ERC1155Supply, NFTBase,
    ReentrancyGuard
{
    string public name;
    string public version;
    string private base_uri;
    address payable private admin;

    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");
    bytes32 public constant URI_SETTER_ROLE     = keccak256("URI_SETTER_ROLE");
    bytes32 public constant MINTER_ROLE         = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE         = keccak256("BURNER_ROLE");
    bytes32 public constant PAUSER_ROLE         = keccak256("PAUSER_ROLE");

    mapping(uint256 => NFT) NFTReserves;
    mapping(uint256 => uint256) tokenHistory;
    using Counters for Counters.Counter;
    Counters.Counter public tokenCounter;

    constructor(string memory _name, string memory _version, string memory _base_uri) ERC1155(_base_uri) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(URI_SETTER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(BURNER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        admin = payable(msg.sender);
        base_uri = _base_uri;
        version = _version;
        name = _name;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Internally used with additional functionallity. (see: mintNFT)
     */
    function mint(address account, uint256 tokenId, uint256 amount, bytes memory data)
        internal
    {
        _mint(account, tokenId, amount, data);
        updateReserve(tokenId, amount);
    }

    /**
     * @dev Required override.
     */
    function _beforeTokenTransfer(address operator, address from, address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)
        internal
        whenNotPaused
        override(ERC1155, ERC1155Supply)
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /**
     * @dev Required override.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @dev 'reserved()' must contain false, only new tokenId's can be reserved.
     */
    function reserveNFT(uint256 tokenId, uint256 amount, string memory _uri, uint256 limit, bool lockUsers) 
        public
        reserved(NFTReserves[tokenId], false)
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        NFT storage reserve = NFTReserves[tokenId];
        reserve.id = tokenId;
        reserve.uri = _uri;
        reserve.max = amount;
        reserve.limit = limit;
        reserve.isset = true;
        reserve.lock[NFTRestriction.LockType.Users] = lockUsers;
        tokenHistory[tokenCounter.current()] = tokenId;
        tokenCounter.increment();
    }
    
    function NFTReserved(uint256 tokenId) public view returns(bool){
        return NFTReserves[tokenId].isset;
    }

    function resetLimit(uint256 tokenId, uint256 limit) 
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if(limit < NFTReserves[tokenId].cur)
            limit = NFTReserves[tokenId].cur;
        NFTReserves[tokenId].limit = limit;
    }

    function updateReserve(uint256 tokenId, uint256 amount) internal {
        NFT storage reserve = NFTReserves[tokenId];
        reserve.cur += amount;
        if(reserve.cur == reserve.max)
            reserve.lock[NFTRestriction.LockType.Global] = true;
    }

    /**
     * @dev Only minter role. Restricted by reserve max & global lock,
     * 'reserved()' must contain true, only existing tokenId's can be minted.
     */
    function mintNFT_Admin(uint256 tokenId, uint256 amount, bytes memory data) 
        public
        nonReentrant()
        reserved(NFTReserves[tokenId], true)
        mintLock(NFTReserves[tokenId], uint8(NFTRestriction.LockType.Global))
        restrictByMax(NFTReserves[tokenId], amount)
        onlyRole(MINTER_ROLE)
    {
        mint(admin, tokenId, amount, data);
    }

    /**
     * @dev Everyone. Restricted by reserve limit & global/user locks,
     * 'reserved()' must contain true, only existing tokenId's can be minted.
     */
    function mintNFT(address to, uint256 tokenId, uint256 amount) 
        public payable
        nonReentrant()
        reserved(NFTReserves[tokenId], true)
        mintLock(NFTReserves[tokenId], uint8(NFTRestriction.LockType.Users))
        restrictByLimit(NFTReserves[tokenId], amount)
        validateFees(NFTReserves[tokenId], amount)
        returns(bool)
    {
        mint(to, tokenId, amount, "");
        admin.transfer(msg.value);
        return true;
    }

    /**
     * @dev For opensea's tokenId mapping.
     */
    function baseTokenURI()
        public view
        returns(string memory)
    {
        return base_uri;
    }

    function setBaseTokenURI(string memory _base_uri) 
        public 
        onlyRole(URI_SETTER_ROLE)
    {
        base_uri = _base_uri;
    }

    /**
     * @dev Based on opensea's ERC1155 standard.
     * @param tokenId is used to fetch token uri.
     */
    function uri(uint256 tokenId) public view override returns(string memory){
        return string(
            abi.encodePacked(
                base_uri,
                NFTReserves[tokenId].uri
            )
        );
    }

    function setTokenUri(uint256 tokenId, string memory _uri) 
        public
        onlyRole(URI_SETTER_ROLE) {
        NFTReserves[tokenId].uri = _uri;
    }

    function lockUnlock(uint256 tokenId) 
        public
        mintLock(NFTReserves[tokenId], uint8(NFTRestriction.LockType.Global))
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        NFTReserves[tokenId].lock[NFTRestriction.LockType.Users] = !NFTReserves[tokenId].lock[NFTRestriction.LockType.Users];
    }

    function getPrice(uint256 tokenId) 
        public view 
        returns(uint256 price)
    {
        return NFTReserves[tokenId].price;
    }

    function setPrice(uint256 tokenId, uint256 price) 
        public 
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        NFTReserves[tokenId].price = price;
    }

    function reservedTokens() public view returns(uint256[] memory tokens){
        tokens = new uint256[](tokenCount());
        for(uint256 i = 0; i < tokenCount(); i++)
            tokens[i] = tokenHistory[i];
    }
    
    function tokenCount() internal view returns(uint256){
        return tokenCounter.current();
    }

    function mintLimit(uint256 tokenId) public view returns(uint256){
        return NFTReserves[tokenId].limit;
    }

    function mintMax(uint256 tokenId) public view returns(uint256){
        return NFTReserves[tokenId].max;
    }
    
    function totalMinted(uint256 tokenId) public view returns(uint256){
        return NFTReserves[tokenId].cur;
    }
}