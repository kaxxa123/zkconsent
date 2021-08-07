const BLAKE2s = require("blake2s")

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


a_pk = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9";
rho  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

var h = new BLAKE2s(32)
h.update(a_pk + rho, 'hex')

cm_hex = h.digest('hex')
cm_dec = hexToDec(cm_hex)

console.log(cm_hex)
console.log(cm_dec)
