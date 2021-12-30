const fs = require('fs')
const Web3 = require('web3');
const BigNumber = require('bignumber.js');

// node app.js  base --server 'http://127.0.0.1:8545' --filename data/basestats.csv --start 13527859 --end 13717847

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

    if (filename)
        console.log(`Processing Block# ${blkNum} having ${totTrn} transactions`);

    report(filename, `${blkNum}, ${totTrn}, ${blk.baseFeePerGas}, ${blk.gasLimit}, ${blk.gasUsed}\n`);    
}

async function blockRangeBase(httpServer, filename, start, end) {

    let web3 = new Web3(new Web3.providers.HttpProvider(httpServer));
    report(filename, "Block, Total_Trns, BaseGasFee, BlockGasLimit, BlockGasUsed\n", true);
    
    for (cntBlk = start; cntBlk <= end; ++cntBlk) {
        await blockDump(web3, cntBlk, filename);
    }
}

module.exports ={
    blockRangeBase
} 
