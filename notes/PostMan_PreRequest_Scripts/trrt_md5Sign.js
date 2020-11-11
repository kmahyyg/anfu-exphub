var str_1 = pm.environment.get("appEnterpriseID");
var str_2 = pm.environment.get("appToken");
var str_3 = Math.round((new Date()).getTime() / 1000).toString();
pm.environment.set("unixTimeStamp", str_3);
var finalSign = CryptoJS.MD5(str_1 + str_2 + str_3).toString();
pm.environment.set("md5Sign", finalSign);
