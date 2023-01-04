const { ethers } = require('hardhat');
const { expect } = require('chai');

describe('[Challenge] The rewarder', function () {
    const TOKENS_IN_LENDER_POOL = 1000000n * 10n ** 18n; // 1 million tokens
    let users, deployer, alice, bob, charlie, david, player;

    before(async function () {
        /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */

        [deployer, alice, bob, charlie, david, player] = await ethers.getSigners();
        users = [alice, bob, charlie, david];

        const FlashLoanerPoolFactory = await ethers.getContractFactory('FlashLoanerPool', deployer);
        const TheRewarderPoolFactory = await ethers.getContractFactory('TheRewarderPool', deployer);
        const DamnValuableTokenFactory = await ethers.getContractFactory('DamnValuableToken', deployer);
        const RewardTokenFactory = await ethers.getContractFactory('RewardToken', deployer);
        const AccountingTokenFactory = await ethers.getContractFactory('AccountingToken', deployer);

        this.liquidityToken = await DamnValuableTokenFactory.deploy();
        this.flashLoanPool = await FlashLoanerPoolFactory.deploy(this.liquidityToken.address);

        // Set initial token balance of the pool offering flash loans
        await this.liquidityToken.transfer(this.flashLoanPool.address, TOKENS_IN_LENDER_POOL);

        this.rewarderPool = await TheRewarderPoolFactory.deploy(this.liquidityToken.address);
        this.rewardToken = RewardTokenFactory.attach(await this.rewarderPool.rewardToken());
        this.accountingToken = AccountingTokenFactory.attach(await this.rewarderPool.accountingToken());

        // Alice, Bob, Charlie and David deposit tokens
        let depositAmount = 100n * 10n ** 18n; 
        for (let i = 0; i < users.length; i++) {
            await this.liquidityToken.transfer(users[i].address, depositAmount);
            await this.liquidityToken.connect(users[i]).approve(this.rewarderPool.address, depositAmount);
            await this.rewarderPool.connect(users[i]).deposit(depositAmount);
            expect(
                await this.accountingToken.balanceOf(users[i].address)
            ).to.be.eq(depositAmount);
        }
        expect(await this.accountingToken.totalSupply()).to.be.eq(depositAmount * BigInt(users.length));
        expect(await this.rewardToken.totalSupply()).to.be.eq(0);

        // Advance time 5 days so that depositors can get rewards
        await ethers.provider.send("evm_increaseTime", [5 * 24 * 60 * 60]); // 5 days
        
        // Each depositor gets reward tokens
        let rewardsInRound = await this.rewarderPool.REWARDS();
        for (let i = 0; i < users.length; i++) {
            await this.rewarderPool.connect(users[i]).distributeRewards();
            expect(
                await this.rewardToken.balanceOf(users[i].address)
            ).to.be.eq(rewardsInRound.div(users.length));
        }
        expect(await this.rewardToken.totalSupply()).to.be.eq(rewardsInRound);

        // Player starts with zero DVT tokens in balance
        expect(await this.liquidityToken.balanceOf(player.address)).to.eq(0);
        
        // Two rounds must have occurred so far
        expect(await this.rewarderPool.roundNumber()).to.be.eq(2);
    });

    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
    });

    after(async function () {
        /** SUCCESS CONDITIONS - NO NEED TO CHANGE ANYTHING HERE */
        // Only one round must have taken place
        expect(
            await this.rewarderPool.roundNumber()
        ).to.be.eq(3);

        // Users should get neglegible rewards this round
        for (let i = 0; i < users.length; i++) {
            await this.rewarderPool.connect(users[i]).distributeRewards();
            const userRewards = await this.rewardToken.balanceOf(users[i].address);
            const delta = userRewards.sub((await this.rewarderPool.REWARDS()).div(users.length));
            expect(delta).to.be.lt(10n ** 16n)
        }
        
        // Rewards must have been issued to the player account
        expect(await this.rewardToken.totalSupply()).to.be.gt(await this.rewarderPool.REWARDS());
        const playerRewards = await this.rewardToken.balanceOf(player.address);
        expect(playerRewards).to.be.gt(0);

        // The amount of rewards earned should be close to total available amount
        const delta = (await this.rewarderPool.REWARDS()).sub(playerRewards);
        expect(delta).to.be.lt(10n ** 17n);

        // Balance of DVT tokens in player and lending pool hasn't changed
        expect(await this.liquidityToken.balanceOf(player.address)).to.eq(0);
        expect(
            await this.liquidityToken.balanceOf(this.flashLoanPool.address)
        ).to.eq(TOKENS_IN_LENDER_POOL);
    });
});
