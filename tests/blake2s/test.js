const BLAKE2s = require("blake2s")

function ModSubtraction(p)
{
    for (i = 0; i < p; ++i)
        for (j = 0; j < p; ++j)
        {
            diff = (i - j) 
            res  = (diff >= 0) ? diff % p : p - diff;

            // console.log(`(${i} - ${j}) % ${p} = ${res}`);
            // if (res == 0)   console.log("^^^^^^^^^^^^^^^^^");

            if (res == 0)   
                console.log(`(${i} - ${j}) % ${p} = ${res}`);
        }
}

//https://stackoverflow.com/questions/21667377/javascript-hexadecimal-string-to-decimal-string
function hexToDec(s) {
    var i, j, digits = [0], carry;
    for (i = 0; i < s.length; i += 1) {
        carry = parseInt(s.charAt(i), 16);
        for (j = 0; j < digits.length; j += 1) {
            digits[j] = digits[j] * 16 + carry;
            carry = digits[j] / 10 | 0;
            digits[j] %= 10;
        }
        while (carry > 0) {
            digits.push(carry % 10);
            carry = carry / 10 | 0;
        }
    }
    return digits.reverse().join('');
}


a_pk    = "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"
rho     = "FFFF000000000000000000000000000000000000000000000000000000009009"
trap_r  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
studyid = "2F0000000000000F"
cm      = "104233707326581956155878965211552591892620143524616864409706009242461667751082"

var hid = new BLAKE2s(32)
hid.update(a_pk + rho, 'hex')

cm_hex = hid.digest('hex')
cm_dec = hexToDec(cm_hex)

console.log("=== Identity Commitment ===")
console.log(cm_hex)
console.log(cm_dec)
console.log()

var hconsentOFF = new BLAKE2s(32)
hconsentOFF.update(trap_r + a_pk + rho + studyid + "00", 'hex')

cm_hex = hconsentOFF.digest('hex')
cm_dec = hexToDec(cm_hex)

console.log("=== Consent Commitment OFF ===")
console.log(cm_hex)
console.log(cm_dec)
console.log()


var hconsentON = new BLAKE2s(32)
hconsentON.update(trap_r + a_pk + rho + studyid + "01", 'hex')

cm_hex = hconsentON.digest('hex')
cm_dec = hexToDec(cm_hex)

console.log("=== Consent Commitment ON ===")
console.log(cm_hex)
console.log(cm_dec)
console.log()

// ModSubtraction(30);