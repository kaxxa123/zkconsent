const fs = require('fs')
const Web3 = require('web3');

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
        
        if (cntTrn == 0)
            console.log(rcpt)

        buffer += `${blkNum}, \"${trn}\", ${rcpt.gasUsed}, ${trn.gasPrice}, ${trn.value}\n`;
        // buffer += `${blkNum}, \"${trn.hash}\", \"${trn.from}\", \"${trn.to}\", ${rcpt.gasUsed}, ${trn.gasPrice}, ${trn.value}\n`;
    }

    report(filename, buffer);
}

async function blockRangeDump(httpServer, filename, start, end) {

    let web3 = new Web3(new Web3.providers.HttpProvider(httpServer));

    report(filename, "Block, Transaction, From, To, GasUsed, GasPrice, Value\n", true);

    for (cntBlk = start; cntBlk <= end; ++cntBlk) {
        await blockDump(web3, cntBlk, filename);
    }
}

module.exports ={
    blockRangeDump
} 
