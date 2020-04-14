
type MyRecord: record{
	url:string;
	code:int;
	rp_time:time;
};


global RelationTable :table[addr] of set[MyRecord];


function justify(orig_addr: addr,s_time:time): int{
	local rep_all:count = 0;
	local rep_404:count = 0;
	local uri_404:set[string];
	for(x in RelationTable[orig_addr]){
		if(|x$rp_time - s_time|<|10 min|){
			rep_all += 1;
			if(x$code == 404){
				rep_404 +=1;
				add uri_404[x$url];
			}
		}
	}
	if(rep_404>2){
		if(rep_404/rep_all > 0.2){
			if(|uri_404|/rep_404 >0.5){
				print fmt("%s is a scaner with %d scan attemps on %d urls",orig_addr,rep_404,|uri_404|);
			}
		}
	}
	return 0;
}


event http_reply(c:connection; version:string; code:count; reason:string;)
{
local orig_addr : addr = c$id$orig_h;
local New_record= MyRecord($url=c$http$uri,$code = code,$rp_time = c$start_time);
if(c$http?$uri){
if (orig_addr in RelationTable) {
			add RelationTable[orig_addr][New_record];
		} else {
			RelationTable[orig_addr] = set(New_record);
		}
}
justify(orig_addr,c$start_time);
}