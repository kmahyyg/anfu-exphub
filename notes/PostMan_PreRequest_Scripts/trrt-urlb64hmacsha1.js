

// Set TimeStr
var moment = require('moment')
// UTC with ISO8601 Format, BUT TIMEZONE IS UTC+8
var currentTimeStr = moment().format("YYYY-MM-DDTHH:mm:ss").toString() + "Z";
pm.environment.set("isoTimestr", currentTimeStr);
// Parse All URL Params
var oriParamsString = request.url.split('?')[1];
if (oriParamsString) {
    var oriEachParamArray = oriParamsString.split('&');
    let oriParams = {};
    oriEachParamArray.forEach((param) => {
        const key = param.split('=')[0];
        const value = param.split('=')[1];
        Object.assign(oriParams, {[key]: value});
    });
} else {
    var oriEachParamArray = new Array();
}
// Build Public Params
var publicData = {
    'AccessKeyId': pm.environment.get('accessKeyID'),
    'Expires': pm.environment.get('expirePeriod'),
    'Timestamp': encodeURIComponent(pm.environment.get('isoTimestr')),
};
// Assign Public Params
Object.keys(publicData).forEach((param) => {
    const key = param;
    const value = publicData[param];
    var finalData = key + '=' + value;
    oriEachParamArray.push(finalData);
});
// Sort Data
pm.request.url.query = oriEachParamArray.sort();
// Build QueryString since pm.request.url.getQueryString() is not working.
var toSign = '';
pm.request.url.query.forEach((param) => {
    toSign += param + "&";
})
toSign = toSign.slice(0,-1);
// Generate Signature
var signData = CryptoJS.HmacSHA1(toSign, pm.environment.get("accessKeySecret")).toString(CryptoJS.enc.Base64);
var finalSign = encodeURIComponent(signData);
// Append Signature as URL Parameter
pm.request.url.query.add('Signature='+finalSign);
// Done


