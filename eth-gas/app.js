// npm init -y
// npm install web3
// npm install bignumber.js
// npm install yargs
// npm install is-valid-path

//10460735 = Jul-15-2020 12:00:04 AM +UTC
//10661251 = Aug-15-2020 12:00:36 AM +UTC

//node app.js stats --server 'http://127.0.0.1:8545' --filename data/stats.csv --start 10460735 --end 10661251

const yargs = require('yargs');
const read_gas_dump = require('./read_gas_dump');
const read_gas_stats = require('./read_gas_stats');
const read_gas_base = require('./read_gas_base');
const isValid = require('is-valid-path');

function Validate(argv) {
    //Validate optional parameters
    if (argv.filename && !isValid(argv.filename)) {
        console.log("Error invalid file path");
        return undefined;
    }

    if (!argv.end) argv.end = argv.start;

    return argv;
}

yargs.version("1.1.0")

let builderParams =  {
        server: {
            describe: 'HTTP node end-point',
            demandOption: true,
            type: 'string'
        },
        filename: {
            describe: 'Output filename',
            demandOption: false,
            type: 'string'
        },
        start: {
            describe: 'Start Block',
            demandOption: true,
            type: 'number'
        },
        end: {
            describe: 'End Block',
            demandOption: false,
            type: 'number'
        }
    };

yargs.command({
    command:    'dump',
    describe:   'Dump transaction fees for given block range',
    builder:    builderParams,
    async handler(argv) {

        validArgs = Validate(argv);
        if (!validArgs)
            return;

        await read_gas_dump.blockRangeDump(validArgs.server, validArgs.filename, validArgs.start, validArgs.end);
    }
});

yargs.command({
    command:    'stats',
    describe:   'Compute MEAN and MEDIAN gas price values for each block in given range',
    builder:    builderParams,
    async handler(argv) {

        validArgs = Validate(argv);
        if (!validArgs)
            return;

        await read_gas_stats.blockRangeStats(validArgs.server, validArgs.filename, validArgs.start, validArgs.end);
    }
});

yargs.command({
    command:    'base',
    describe:   'Extract Base Gas Fees for each block in given range',
    builder:    builderParams,
    async handler(argv) {

        validArgs = Validate(argv);
        if (!validArgs)
            return;

        await read_gas_base.blockRangeBase(validArgs.server, validArgs.filename, validArgs.start, validArgs.end);
    }
});

yargs.parse();



