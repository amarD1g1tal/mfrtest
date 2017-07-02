


$('#readTagBtn').on('click',function(){
        cordova.exec(callback, function(err) {
    
        callback('Nothing to echo.');
        
        }, "MifareTest", "readTag", []);
});

function callback(arg){
    alert(arg);
}