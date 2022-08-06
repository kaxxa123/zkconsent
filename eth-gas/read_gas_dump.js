const fs = require('fs')
const Web3 = require('web3');
const BigNumber = require('bignumber.js');

// node app.js  dump --server 'http://127.0.0.1:8545' --filename data/stats.csv --start 13690000 --end 13690100

function report(filename, text, clear) {
    if (filename) {
        if (clear)
                fs.writeFileSync(filename, text);
        else    fs.writeFileSync(filename, text, {flag: "a"});
    }
    else process.stdout.write(text);
}

async function blockDump(web3, blkNum, filename) {
    
    let blk = await web3.eth.getBlock(blkNum);
    let totTrn = blk.transactions.length;
    let buffer = "";

    if (filename)
        console.log(`Processing Block# ${blkNum} having ${totTrn} transactions`);

    for (cntTrn = 0; cntTrn < totTrn; ++cntTrn) {
        let trn = blk.transactions[cntTrn];
        let rcpt = await web3.eth.getTransactionReceipt(trn);
        let price = BigNumber(rcpt.effectiveGasPrice);       

        buffer += `${blkNum}, \"${trn}\", ${rcpt.type}, ${rcpt.gasUsed}, ${price.toString()}, \"${rcpt.from}\", \"${rcpt.to}\"\n`;
    }

    report(filename, buffer);
}

async function blockRangeDump(httpServer, filename, start, end) {

    let web3 = new Web3(new Web3.providers.HttpProvider(httpServer));
    report(filename, "Block, Transaction, Type, GasUsed, GasPrice, From, To\n", true);

    for (cntBlk = start; cntBlk <= end; ++cntBlk) {
        await blockDump(web3, cntBlk, filename);
    }
}

module.exports ={
    blockRangeDump
} 
