const fs = require('fs')
const Web3 = require('web3');
const BigNumber = require('bignumber.js');

function report(filename, text, clear) {
    if (filename) {
        if (clear)
                fs.writeFileSync(filename, text);
        else    fs.writeFileSync(filename, text, {flag: "a"});
    }
    else process.stdout.write(text);
}

function getBNMedian(bnArray) {

    bnArray = bnArray.sort((a,b) => { 
                    if (a.isLessThan(b)) return -1;
                    else if (a.isGreaterThan(b)) return 1;
                    return 0;
                });

    const mid = Math.floor(bnArray.length/2);

    return (bnArray.length % 2 !== 0 ) ? bnArray[mid] :
                                        (bnArray[mid-1].plus(bnArray[mid])).dividedToIntegerBy(2);
}

async function blockStats(web3, accounts, blkNum, filename) {
    
    let blk = await web3.eth.getBlock(blkNum, {from: accounts[0]});
    let totTrn = blk.transactions.length;
    let gasArray = [];
    let total = BigNumber(0);

    if (filename)
        console.log(`Processing Block# ${blkNum} having ${totTrn} transactions`);

    for (cntTrn = 0; cntTrn < totTrn; ++cntTrn) {
        let trn = blk.transactions[cntTrn];
        let price = BigNumber(trn.gasPrice);

        gasArray.push(price);
        total = total.plus(price);
    }

    if (totTrn > 0) {
        //Find median
        const median = getBNMedian(gasArray);
        const mean = total.dividedToIntegerBy(totTrn);

        //Log data
        report(filename, `${blkNum}, ${totTrn}, ${mean.toString()}, ${median.toString()}\n`)
    }
}

async function blockRangeStats(httpServer, filename, start, end) {
    let web3 = new Web3(new Web3.providers.HttpProvider(httpServer));
    let accounts = await web3.eth.getAccounts();

    report(filename, "Block, Total_Trns, Mean_GasPrice, Median_GasPrice\n", true);

    for (cntBlk = start; cntBlk <= end; ++cntBlk) {
        await blockStats(web3, accounts, cntBlk, filename);
    }
}

module.exports ={
    blockRangeStats
} 
