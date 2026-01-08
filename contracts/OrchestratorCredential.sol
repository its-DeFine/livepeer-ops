pragma solidity ^0.8.20;

interface IOrchestratorRegistry {
    function isRegistered(address orchestrator) external view returns (bool);
}

interface IBondingManager {
    function transcoderTotalStake(address transcoder) external view returns (uint256);
}

contract OrchestratorCredential {
    string public constant name = "Embody Orchestrator Credential";
    string public constant symbol = "EOC";

    address public owner;
    address public registry;
    address public bondingManager;
    uint256 public minStake;

    mapping(uint256 => address) private _owners;
    mapping(address => address) private _delegates;
    mapping(address => uint256) private _balances;

    event CredentialMinted(address indexed owner, uint256 indexed tokenId, address delegate);
    event DelegateUpdated(address indexed owner, address delegate);
    event CredentialBurned(address indexed owner, uint256 indexed tokenId, address burner);
    event RegistryUpdated(address registry);
    event BondingManagerUpdated(address bondingManager);
    event MinStakeUpdated(uint256 minStake);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    constructor(address registry_, address bondingManager_, uint256 minStake_) {
        owner = msg.sender;
        registry = registry_;
        bondingManager = bondingManager_;
        minStake = minStake_;
    }

    function tokenIdFor(address orchestrator) public pure returns (uint256) {
        return uint256(uint160(orchestrator));
    }

    function balanceOf(address orchestrator) public view returns (uint256) {
        require(orchestrator != address(0), "zero address");
        return _balances[orchestrator];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner_ = _owners[tokenId];
        require(owner_ != address(0), "token not found");
        return owner_;
    }

    function delegateOf(address orchestrator) public view returns (address) {
        return _delegates[orchestrator];
    }

    function delegateOfToken(uint256 tokenId) public view returns (address) {
        address owner_ = _owners[tokenId];
        require(owner_ != address(0), "token not found");
        return _delegates[owner_];
    }

    function mint(address orchestrator, address delegate) external {
        require(orchestrator != address(0), "owner required");
        require(delegate != address(0), "delegate required");
        require(_balances[orchestrator] == 0, "credential exists");
        require(_eligible(orchestrator), "not eligible");

        uint256 tokenId = tokenIdFor(orchestrator);
        _owners[tokenId] = orchestrator;
        _balances[orchestrator] = 1;
        _delegates[orchestrator] = delegate;

        emit CredentialMinted(orchestrator, tokenId, delegate);
        emit Transfer(address(0), orchestrator, tokenId);
    }

    function updateDelegate(address orchestrator, address newDelegate) external {
        require(msg.sender == orchestrator, "owner only");
        require(_balances[orchestrator] == 1, "no credential");
        require(newDelegate != address(0), "delegate required");
        _delegates[orchestrator] = newDelegate;
        emit DelegateUpdated(orchestrator, newDelegate);
    }

    function burn(uint256 tokenId) external {
        address owner_ = _owners[tokenId];
        require(owner_ != address(0), "token not found");
        address delegate = _delegates[owner_];
        require(msg.sender == owner_ || msg.sender == delegate, "not authorized");

        delete _owners[tokenId];
        delete _balances[owner_];
        delete _delegates[owner_];

        emit CredentialBurned(owner_, tokenId, msg.sender);
        emit Transfer(owner_, address(0), tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(to == address(0), "non-transferable");
        require(from == ownerOf(tokenId), "not owner");
        burn(tokenId);
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert("non-transferable");
    }

    function safeTransferFrom(address, address, uint256, bytes calldata) external pure {
        revert("non-transferable");
    }

    function approve(address, uint256) external pure {
        revert("non-transferable");
    }

    function setApprovalForAll(address, bool) external pure {
        revert("non-transferable");
    }

    function getApproved(uint256) external pure returns (address) {
        return address(0);
    }

    function isApprovedForAll(address, address) external pure returns (bool) {
        return false;
    }

    function updateRegistry(address registry_) external onlyOwner {
        registry = registry_;
        emit RegistryUpdated(registry_);
    }

    function updateBondingManager(address bondingManager_) external onlyOwner {
        bondingManager = bondingManager_;
        emit BondingManagerUpdated(bondingManager_);
    }

    function updateMinStake(uint256 minStake_) external onlyOwner {
        minStake = minStake_;
        emit MinStakeUpdated(minStake_);
    }

    function _eligible(address orchestrator) internal view returns (bool) {
        if (registry != address(0)) {
            if (!IOrchestratorRegistry(registry).isRegistered(orchestrator)) {
                return false;
            }
        }
        if (bondingManager != address(0)) {
            uint256 stake = IBondingManager(bondingManager).transcoderTotalStake(orchestrator);
            if (stake < minStake) {
                return false;
            }
        }
        return true;
    }
}
