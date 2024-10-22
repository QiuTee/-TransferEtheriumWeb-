// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TransactionFactory {
    address[] public deployedTransactions;

    function createTransaction(uint _amount, address _receiver) public payable {
        require(_amount > 0, "Amount must be greater than 0");
        require(msg.value >= _amount, "Insufficient Ether sent");
        Transaction newTransaction = new Transaction{value: _amount}(
            msg.sender,
            _receiver
        );
        deployedTransactions.push(address(newTransaction)); // Store the address of the newTransaction
    }

    function getDeployedTransactions() public view returns (address[] memory) {
        return deployedTransactions;
    }
}

contract Transaction {
    address public manager;
    address public receiver;
    uint public amount;
    bool public complete;
    uint public timestamp;

    modifier onlyManager() {
        require(msg.sender == manager);
        _;
    }

    modifier onlyReceiver() {
        require(msg.sender == receiver);
        _;
    }

    constructor(address _sender, address _receiver) payable {
        manager = _sender;
        receiver = _receiver;
        amount = msg.value; // Set the amount of Ether sent with the transaction
        complete = false;
        timestamp = block.timestamp; // Set the current timestamp when the transaction is created
    }

    event TransactionCompleted(
        address sender,
        address receiver,
        uint amount,
        uint timestamp
    );

    function send() public payable onlyManager {
        require(!complete, "Transaction already completed"); // Ensure the transaction is not already completed
        require(
            address(this).balance > 0,
            "The Contract Doesn't keep any money"
        );
        payable(receiver).transfer(address(this).balance);
        complete = true;
        emit TransactionCompleted(manager, receiver, amount, block.timestamp);
    }

    function withdraw() public onlyManager {
        require(!complete, "Transaction already completed"); // Ensure the transaction is not already completed
        require(
            address(this).balance > 0,
            "The Contract Doesn't keep any money"
        );
        payable(manager).transfer(address(this).balance);
        complete = true;
        emit TransactionCompleted(manager, manager, amount, block.timestamp);
    }

    function returnInformation()
        public
        view
        returns (address, address, uint, bool, uint, uint)
    {
        return (
            manager,
            receiver,
            amount,
            complete,
            timestamp,
            address(this).balance
        );
    }
}
